"""Inspect actual Foundation request headers on loopback, without external traffic."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import plistlib
import subprocess
import tempfile
import threading

repo = Path(__file__).resolve().parents[1]
received = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        received.append((self.path, {key.lower(): value for key, value in self.headers.items()}))
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/redirect-target')
        elif self.path == '/authentication':
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="fixture"')
        else:
            self.send_response(200)
        self.send_header('Set-Cookie', 'fixture=must-not-return; Path=/')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix='service-privacy-') as scratch:
        app = Path(scratch) / 'DiagnosticFixture.app' / 'Contents'
        (app / 'MacOS').mkdir(parents=True)
        (app / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleName': 'DiagnosticPrivacyFixture', 'CFBundleExecutable': 'DiagnosticPrivacyFixture',
            'CFBundleIdentifier': 'org.example.diagnostic-privacy-fixture',
            'CFBundleVersion': '1', 'CFBundlePackageType': 'APPL',
        }))
        binary = app / 'MacOS/DiagnosticPrivacyFixture'
        subprocess.run(['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-swift-version', '5', '-O',
                        '-parse-as-library', str(repo / 'Sources/ServiceDiagnosticTransport.swift'),
                        str(repo / 'Tests/service_transport_fixture.swift'), '-o', str(binary)], check=True)
        subprocess.run([str(binary), 'http://127.0.0.1:' + str(server.server_port)], check=True, timeout=35)
    assert [path for path, _ in received] == ['/baseline', '/first', '/second', '/redirect', '/authentication'], received
    baseline = received[0][1]
    assert 'DiagnosticPrivacyFixture' in baseline.get('user-agent', ''), 'missing default-header positive control'
    assert baseline.get('accept-language'), 'missing default-locale positive control'
    for path, headers in received[1:]:
        assert not headers.get('user-agent'), (path, 'unexpected user agent')
        assert not headers.get('accept-language'), (path, 'unexpected locale')
        assert not any(key in headers for key in ('cookie', 'authorization', 'referer')), (path, 'unexpected context header')
        assert headers.get('accept') == 'text/plain', (path, 'accept header')
        assert not any('DiagnosticPrivacyFixture' in value or 'claudeguard' in value.lower() for value in headers.values())
    print(json.dumps({'result': 'passed', 'scope': 'Actual Foundation loopback HTTP requests; no external requests',
                      'defaultBundleHeaderObserved': True, 'diagnosticRequests': 4,
                      'bundleIdentitySent': False, 'localeSent': False, 'cookiesReplayed': False,
                      'credentialsSent': False, 'redirectFollowed': False}))
finally:
    server.shutdown()
    server.server_close()
