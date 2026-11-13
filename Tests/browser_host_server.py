"""Bounded loopback host for the shipping WebRTC page during fault acceptance.

Engineering only. No candidate address, credential or packet body is retained.
This host observes the independent driver's sanitized phase; it cannot change
the production guard policy or authorize a release.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COUNTS = ['privateHost', 'publicHost', 'approvedReflexive', 'otherReflexive', 'relay', 'unknown']


def current_phase(report, now):
    if 'left_state' in report or report.get('checks', {}).get('driver_completed', {}).get('result') == 'FAIL':
        return 'unavailable'
    started = report.get('browser_phase_started_at')
    maximum_age = 605 if report.get('browser_phase') in ['waiting-for-browser','protected-open','recovered-open'] else (
        95 if report.get('browser_phase') == 'vpn-disconnected' else 65)
    if type(started) not in [int, float] or not 0 <= now - started <= maximum_age:
        return 'unavailable'
    value = report.get('browser_phase')
    return value if value in ['waiting-for-browser', 'protected-open', 'vpn-disconnected', 'recovered-open'] else 'unavailable'


def main(config_path, output):
    config = json.loads(config_path.read_text())
    token = secrets.token_hex(32)
    evidence = []
    context = {}
    deadline = time.monotonic() + 1200

    def phase():
        try:
            report = json.loads(Path('/var/tmp/org.claudeguard-acceptance-result.json').read_text())
            return current_phase(report, time.time())
        except (OSError, ValueError):
            return 'unavailable'

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, code, body=b'', kind='application/json'):
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def valid_path(self):
            return self.headers.get('Host') == host and self.path.startswith('/' + token + '/')

        def do_GET(self):
            if not self.valid_path():
                self.respond(404)
                return
            name = self.path[len(token)+2:]
            if name == 'config':
                context.update(generation=secrets.token_hex(16), phase=phase())
                self.respond(200, json.dumps(dict(context, expected=config['expected'], language='en', appearance='dark', strings={})).encode())
            elif name == 'phase':
                self.respond(200, json.dumps({'phase': phase()}).encode())
            elif name in ['', 'webrtc.js', 'webrtc.css']:
                file = ROOT / 'Resources/BrowserDiagnostics' / (name or 'webrtc.html')
                body = file.read_bytes()
                if not name:
                    controls = b'''<p id="test-phase" role="status">unavailable</p>
<button id="advance" disabled>Advance acceptance phase</button>
<button id="automate">Start automated acceptance</button>
<script>
const stage = document.getElementById('test-phase');
const advance = document.getElementById('advance');
const automate = document.getElementById('automate');
const runCheck = document.getElementById('run');
let automated = false, checkingPhase = false, lastTestPhase = '', child;
async function acknowledge(value) {
  await fetch('advance', {method:'POST', credentials:'omit', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phase:value})});
}
automate.onclick = async () => {
  if (stage.textContent !== 'waiting-for-browser') return;
  child = window.open('https://claude.ai/login?guard_probe=start', '_blank');
  if (!child) return;
  automated = true; automate.disabled = true;
  await acknowledge('waiting-for-browser');
};
async function samplePhase(value) {
  checkingPhase = true;
  lastTestPhase = value;
  try {
    child.location = 'https://claude.ai/login?guard_probe=' + value + '_' + Date.now();
    const until = Date.now() + 12000;
    while (runCheck.disabled && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 100));
    if (runCheck.disabled) return;
    runCheck.click();
    while (runCheck.disabled && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 100));
    // The operator captures the actual main document before advancing.
  } finally { checkingPhase = false; }
}
async function refreshPhase() {
  try {
    const value = await (await fetch('phase', {cache:'no-store', credentials:'omit'})).json();
    stage.textContent = value.phase;
    advance.disabled = !['protected-open','recovered-open'].includes(value.phase);
    if (automated && !checkingPhase && value.phase !== lastTestPhase &&
        ['protected-open','vpn-disconnected','recovered-open'].includes(value.phase)) samplePhase(value.phase);
  } catch { stage.textContent = 'unavailable'; advance.disabled = true; }
}
advance.onclick = async () => {
  advance.disabled = true;
  await acknowledge(stage.textContent);
  await refreshPhase();
};
refreshPhase(); setInterval(refreshPhase, 500);
</script>'''
                    body = body.replace(b'</body>', controls + b'</body>')
                self.respond(200, body, 'text/html' if not name else ('text/javascript' if name.endswith('.js') else 'text/css'))
            else:
                self.respond(404)

        def do_POST(self):
            try:
                assert self.valid_path() and self.path in ['/' + token + '/result', '/' + token + '/advance']
                assert self.headers.get('Origin') == 'http://' + host
                assert self.headers.get('Content-Type') == 'application/json'
                size = int(self.headers.get('Content-Length', '0'))
                assert 0 < size <= 2048
                data = json.loads(self.rfile.read(size))
                if self.path.endswith('/advance'):
                    assert set(data) == {'phase'} and data['phase'] == phase()
                    assert data['phase'] in ['waiting-for-browser', 'protected-open', 'recovered-open']
                    ack = Path(config['browserBridge']) / (data['phase'] + '.ack')
                    ack.write_bytes(b'advance')
                    ack.chmod(0o600)
                    self.respond(200, b'{}')
                    return
                assert set(data) == set(COUNTS + ['complete', 'generation', 'phase'])
                assert type(data['complete']) is bool
                assert all(type(data[key]) is int and 0 <= data[key] <= 128 for key in COUNTS)
                assert sum(data[key] for key in COUNTS) <= 128
                assert data['generation'] == context['generation'] and data['phase'] == context['phase'] == phase()
                assert data['phase'] != 'unavailable'
                data.pop('generation')
                data['checked_at'] = time.time()
                evidence.append(data)
                output.write_text(json.dumps(evidence, indent=2) + '\n')
                output.chmod(0o600)
                self.respond(200, b'{}')
            except (AssertionError, ValueError, KeyError):
                self.respond(400)

    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.timeout = 1
    host = '127.0.0.1:' + str(server.server_port)
    print('http://' + host + '/' + token + '/', flush=True)
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == '__main__':
    assert len(sys.argv) == 3
    main(Path(sys.argv[1]), Path(sys.argv[2]))
