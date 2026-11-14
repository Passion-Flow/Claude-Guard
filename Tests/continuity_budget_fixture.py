"""Exercise the production independent client with real delayed loopback TLS.

The destination, existing permission and route facts are local fixture controls.
Production DNS parsing, cache decisions, TLS transport and client scheduling run
unchanged. No installed service, system clock or trust store is modified.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import json
import shlex
import ssl
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--worker', type=Path)
parser.add_argument('--expect-legacy', action='store_true')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
worker = args.worker or repo / 'Sources/GuardWorker.sh'
definitions = worker.read_text().split('action=${1-}')[0]
assert definitions.count('tunnel_response() {') == 1
definitions = definitions.replace('tunnel_response() {', 'fixture_actual_transport() {')
cases = {
    'slow-dns': (2.3, .05, 1, False),
    'slow-target': (.01, 5.2, 60, False),
    'stalled-dns': (4.5, .01, 60, False),
    'combined-deadline': (3.1, 6, 60, False),
    'invalid-dns': (.01, .01, 60, True),
    'cached-target': (.01, 6.2, 60, False),
}
requests = []
request_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        case, kind = self.path.strip('/').split('/')
        dns_delay, target_delay, ttl, invalid = cases[case]
        with request_lock:
            requests.append((case, kind))
        time.sleep(dns_delay if kind == 'dns' else target_delay)
        document = {'Status': 0, 'TC': invalid,
                    'Question': [{'name': 'checkip.amazonaws.com', 'type': 1}],
                    'Answer': [{'name': 'checkip.amazonaws.com', 'type': 1,
                                'data': '9.9.9.9', 'TTL': ttl}]}
        body = json.dumps(document).encode() if kind == 'dns' else b'9.9.9.9\n'
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        self.close_connection = True

    def log_message(self, *_):
        pass


with tempfile.TemporaryDirectory(prefix='guard-continuity-budget-') as temporary:
    root = Path(temporary)
    config = root / 'certificate.conf'
    config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n'
                      '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                      'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n')
    certificate, key = root / 'certificate.pem', root / 'key.pem'
    subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-config', str(config), '-keyout', str(key),
                    '-out', str(certificate)], check=True, capture_output=True)
    key.chmod(0o600)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate, key)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    results = []
    try:
        for case in (['slow-dns', 'slow-target'] if args.expect_legacy else cases):
            directory = root / case
            health = directory / 'health'
            (health / 'independent').mkdir(parents=True, mode=0o700)
            cache = directory / 'cache'
            if case == 'cached-target':
                cache.write_text(f'9.9.9.9|{int(time.time())}|60|checkip.amazonaws.com\n')
            budgets = directory / 'budgets'
            settings = f'''
directory={shlex.quote(str(directory))}
health_round={shlex.quote(str(health))}
health_cache_file={shlex.quote(str(cache))}
phase=OPEN; health_request_budget=8; iface=lo0; peer=192.0.2.7
risk_fresh() {{ return 0; }}
route_via_tunnel() {{ [ "$1" = 8.8.8.8 ] || [ "$1" = 9.9.9.9 ]; }}
tunnel_response() {{
  fixture_kind=target
  case "$*" in *dns.google*) fixture_kind=dns;; esac
  printf '%s|%s\\n' "$fixture_kind" "$1" >> {shlex.quote(str(budgets))}
  fixture_actual_transport "$1" --cacert {shlex.quote(str(certificate))} \
    --resolve {shlex.quote(f'localhost:{server.server_port}:127.0.0.1')} \
    "https://localhost:{server.server_port}/{case}/$fixture_kind"
}}
start_health_client independent
wait "$health_independent_pid" || true
'''
            began = time.monotonic()
            result = subprocess.run(['/bin/sh', '-c', definitions + settings],
                                    capture_output=True, text=True, timeout=12)
            elapsed = time.monotonic() - began
            assert result.returncode == 0, (case, result.stderr)
            accepted = (health / 'independent.stamp').exists()
            expected = case in ('slow-dns', 'slow-target', 'cached-target')
            if args.expect_legacy and case == 'slow-dns':
                expected = False
            assert accepted == expected, (case, accepted, elapsed)
            if accepted:
                assert (health / 'independent.trace').read_text().strip() == '9.9.9.9'
            records = [line.split('|') for line in budgets.read_text().splitlines()]
            for _, budget in records:
                assert 0 < int(budget) <= 8, (case, records)
            if case == 'slow-dns' and not args.expect_legacy:
                # A one-second TTL is not inflated to avoid the next resolution.
                assert cache.read_text().strip().split('|')[2:] == ['1', 'checkip.amazonaws.com']
                assert elapsed < 8, elapsed
            if case == 'combined-deadline':
                assert elapsed < 8.5, elapsed
                assert [kind for kind, _ in records] == ['dns', 'target']
            if case in ('stalled-dns', 'invalid-dns'):
                assert [kind for kind, _ in records] == ['dns']
                assert not cache.exists()
            if case == 'cached-target':
                assert records == [['target', '8']]
            results.append({'case': case, 'observationProduced': accepted,
                            'requests': records, 'seconds': round(elapsed, 3)})
    finally:
        server.shutdown()
        server.server_close()
    print(json.dumps({'result': 'legacy-defect-reproduced' if args.expect_legacy else 'passed',
                      'scope': 'Actual independent client, DNS parser and verified TLS with bounded local delays; no host policy or clock changes',
                      'cases': results}))
