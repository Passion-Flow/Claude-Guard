"""Exercise risk renewal with real verified loopback TLS and incomplete HTTP bodies.

Only the test destination and OS route facts are substituted. The production
curl wrapper, risk parser, cache and renewal decisions execute unchanged. No
installed service, network policy, system trust store or clock is modified.
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
definitions = definitions.replace('tunnel_response() {', 'fixture_actual_tunnel_response() {')
release_stalled = threading.Event()


def payload(rejected=False):
    return json.dumps({'status': 'ok', '192.0.2.42': {
        'network': {'type': 'Residential'},
        'detections': {'proxy': rejected, 'vpn': False, 'tor': False,
                       'hosting': False, 'anonymous': False, 'compromised': False,
                       'scraper': False, 'risk': 0, 'confidence': 100},
        'last_updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }}).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body = payload(self.path == '/rejected')
        if self.path == '/invalid':
            body = b'{"status":"ok"}'
        elif self.path == '/nul':
            body += b'\x00'
        elif self.path == '/oversized':
            body = b'x' * 17000
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body[:13] if self.path in ('/truncated', '/stalled') else body)
            self.wfile.flush()
            if self.path == '/stalled':
                release_stalled.wait(6)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        self.close_connection = True

    def log_message(self, *_):
        pass


with tempfile.TemporaryDirectory(prefix='guard-risk-transfer-') as temporary:
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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    driver = root / 'RiskDriver.swift'
    driver.write_text('''import Foundation
@main enum RiskDriver {
 static func main() {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  guard let newline = data.firstIndex(of: 10), let context = String(data: data[..<newline], encoding: .utf8) else { exit(2) }
  let fields = context.components(separatedBy: "|")
  guard fields.count == 3 else { exit(2) }
  exit(GuardRiskPolicy.evaluateKeyless(Data(data[data.index(after: newline)...]), region: fields[0], expected: fields[1], observedRegion: fields[2]).rawValue)
 }
}
''')
    evaluator = root / 'RiskDriver'
    subprocess.run(['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-swift-version', '5',
                    '-O', '-parse-as-library', str(repo / 'Sources/NodeAdmission.swift'),
                    str(repo / 'Sources/GuardRiskPolicy.swift'), str(driver), '-o',
                    str(evaluator)], check=True, capture_output=True)
    results = []
    try:
        cases = ['truncated', 'stalled'] if args.expect_legacy else [
            'complete', 'truncated', 'stalled', 'invalid', 'nul', 'oversized', 'rejected',
            'expired-truncated', 'expired-stalled', 'missing-truncated', 'locked-truncated',
        ]
        for case in cases:
            directory, boot = root / case / 'runtime', root / case / 'boot'
            directory.mkdir(parents=True, mode=0o700)
            boot.mkdir(mode=0o700)
            now = int(time.time())
            original_stamp = now - (3600 if case.startswith('expired-') else 2710)
            original = str(original_stamp).encode() + b'|192.0.2.42|US\n' + payload()
            cache = directory / 'risk-cache'
            missing = case.startswith(('missing-', 'locked-'))
            if not missing:
                cache.write_bytes(original)
            current_stamp = 0 if missing else original_stamp
            initial_phase = 'LOCKED' if case.startswith('locked-') else 'OPEN'
            endpoint = case.split('-')[-1]
            url = f'https://localhost:{server.server_port}/{endpoint}'
            settings = f'''
directory={shlex.quote(str(directory))}; boot_dir={shlex.quote(str(boot))}
risk_evaluator={shlex.quote(str(evaluator))}; risk_key=
observed=192.0.2.42; expected=192.0.2.42; observed_region=US; risk_region=US
session=fixture; vpn_service=fixture; iface=lo0; endpoint_key=fixture; bound_path=fixture
phase={initial_phase}; desired={initial_phase}; reason=probe-ok; last_probe={now}; last_verified={now}
probe_region_source=observed; risk_checked_at={current_stamp}
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
publish() {{ return 0; }}
load_phase() {{ return 0; }}
resolve_risk_api() {{ printf '127.0.0.1'; }}
underlay_snapshot() {{ printf fixture; }}
vpn_connection() {{ printf 'Connected lo0'; }}
probe_route_reason() {{ return 0; }}
tunnel_response() {{
  fixture_actual_tunnel_response "$1" --cacert {shlex.quote(str(certificate))} \
    --resolve {shlex.quote(f'localhost:{server.server_port}:127.0.0.1')} {shlex.quote(url)}
}}
renew_risk_evidence
printf '%s|%s|%s|%s\\n' "$desired" "$reason" "$risk_checked_at" "$last_verified"
'''
            began = time.monotonic()
            result = subprocess.run(['/bin/sh', '-c', definitions + settings],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, (case, result.returncode, result.stderr)
            fields = result.stdout.strip().split('|')
            assert len(fields) == 4, (case, result.stdout)
            phase, reason, risk_stamp, proof_stamp = fields
            exit_code = (directory / 'transport-exit').read_text().strip()
            http = (directory / 'transport-status').read_text().strip()
            assert http == '200', (case, http)
            remaining = cache.read_bytes() if cache.exists() else None
            if args.expect_legacy:
                assert phase == 'LOCKED' and reason == 'risk-invalid-response'
                assert remaining is None and risk_stamp == proof_stamp == '0'
            elif endpoint in ('truncated', 'stalled'):
                if case.startswith('expired-') or missing:
                    assert phase == 'LOCKED' and risk_stamp == proof_stamp == '0', (case, fields)
                else:
                    assert fields == ['OPEN', 'risk-refresh-pending', str(original_stamp), str(now)], (case, fields)
                assert remaining == (None if missing else original), case
                assert exit_code == ('18' if endpoint == 'truncated' else '28'), (case, exit_code)
            elif case == 'complete':
                assert phase == 'OPEN' and int(risk_stamp) >= now and proof_stamp == str(now), fields
                assert remaining is not None and remaining != original
            elif case == 'rejected':
                assert fields == ['LOCKED', 'risk-rejected', '0', '0'], fields
                assert remaining is not None and remaining != original
            else:
                assert fields == ['LOCKED', 'risk-invalid-response', '0', '0'], (case, fields)
                assert remaining is None
            assert not list(directory.glob('probe.*')), case
            if not args.expect_legacy:
                diagnostics = (directory / 'risk-transports').read_text().splitlines()
                assert len(diagnostics) == 1 and len(diagnostics[0].split('|')) == 6, case
                assert not any(marker in diagnostics[0] for marker in (
                    'localhost', '192.0.2.42', 'proxycheck', 'Residential', 'https://')), case
            results.append({'case': case, 'phase': phase, 'reason': reason,
                            'http': http, 'transportExit': int(exit_code),
                            'seconds': round(time.monotonic() - began, 3)})
    finally:
        release_stalled.set()
        server.shutdown()
        server.server_close()
    print(json.dumps({'result': 'legacy-defect-reproduced' if args.expect_legacy else 'passed',
                      'scope': 'Actual production transport and risk decisions with verified loopback TLS; no host policy or clock changes',
                      'cases': results}))
