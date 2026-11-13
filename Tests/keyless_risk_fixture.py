"""Exercise actual shell keyless admission/cache/quota paths without networking."""
from pathlib import Path
import json
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-keyless-') as temporary:
    root = Path(temporary)
    (root / 'runtime').mkdir(mode=0o700)
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
    subprocess.run(['swiftc', '-swift-version', '5', '-O', '-parse-as-library', str(repo / 'Sources/NodeAdmission.swift'), str(repo / 'Sources/GuardRiskPolicy.swift'), str(driver), '-o', str(evaluator)], check=True)
    source = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
    context = f'''\ndirectory='{root}/runtime'
risk_evaluator='{evaluator}'
risk_key=
observed=192.0.2.42
observed_region=US
risk_region=US
phase=LOCKED
load_phase() {{ return 0; }}
resolve_risk_api() {{ printf 93.184.216.34; }}
tunnel_response() {{ printf called >> '{root}/calls'; cat '{root}/response'; }}
if review_exit_risk; then printf '0|%s' "$risk_admission_at"; else printf '%s' "$?"; fi
'''
    def run(issue=False, override=None):
        script = source + (context if override is None else override)
        if issue: script += '\nprintf "|%s" "$risk_issue"\n'
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, check=True)
        return result.stdout
    def response(risk=0, flag=False, confidence=100):
        return {'status': 'ok', '192.0.2.42': {'network': {'type': 'Residential'}, 'detections': {'proxy': flag, 'vpn': False, 'tor': False, 'hosting': False, 'anonymous': False, 'compromised': False, 'scraper': False, 'risk': risk, 'confidence': confidence}, 'last_updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}}
    (root / 'response').write_text(json.dumps(response()))
    first = run()
    assert first.startswith('0|')
    assert run() == first  # cache reuse does not renew the timestamp
    assert (root / 'calls').read_text() == 'called'
    cache = root / 'runtime/risk-cache'
    original = cache.read_text()
    header, body = original.split('\n', 1)
    cache.write_text(str(int(time.time()) - 3601) + '|192.0.2.42|US\n' + body)
    assert run() == '2'  # quota spacing persists even when evidence expires
    assert run(issue=True) == '2|risk-rate-limited'
    (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
    (root / 'response').write_text(json.dumps(response(flag=True)))
    assert run() == '1'
    assert not run().startswith('0|')
    (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
    (root / 'response').write_text('{"status":"ok"}')
    assert run() == '2'
    (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
    assert run(issue=True) == '2|risk-invalid-response'
    (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
    no_dns = context.replace('resolve_risk_api() { printf 93.184.216.34; }', 'resolve_risk_api() { return 1; }')
    assert run(issue=True, override=no_dns) == '2|risk-dns-unavailable'
    unavailable = context.replace("tunnel_response() { printf called >> '" + str(root) + "/calls'; cat '" + str(root) + "/response'; }", 'tunnel_response() { return 1; }')
    assert run(issue=True, override=unavailable) == '2|risk-provider-unavailable'
    for confidence in [0, 25, 89]:
        for flag in [False, True]:
            cache.unlink(missing_ok=True)
            (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
            (root / 'response').write_text(json.dumps(response(flag=flag, confidence=confidence)))
            outcome = run()
            assert outcome == '1' if flag else outcome.startswith('0|')
    print('PASS: keyless actual-worker admission, exact-address cache, original evidence age, rejected/missing facts, restart-persistent quota spacing and positive-detection confidence semantics')
