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
publish() {{ return 0; }}
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
    # Connection-only retries remain inside the same persisted hourly slot.
    # A quota response is terminal, and OPEN renewal never extends the lease
    # with a multi-request retry loop.
    for mode, expected_calls, success in [('transient', 2, True), ('quota', 1, False), ('open', 1, False)]:
        cache.unlink(missing_ok=True)
        (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
        (root / 'response').write_text(json.dumps(response()))
        (root / 'retry-calls').write_text('')
        retry = context.replace("tunnel_response() { printf called >> '" + str(root) + "/calls'; cat '" + str(root) + "/response'; }", f'''tunnel_response() {{
          printf x >> '{root}/retry-calls'
          count=$(/usr/bin/wc -c < '{root}/retry-calls' | /usr/bin/tr -d ' ')
          if [ '{mode}' = transient ] && [ "$count" -ge 2 ]; then /bin/cat '{root}/response'; return 0; fi
          printf '%s' {'429' if mode == 'quota' else '000'} > "$directory/transport-status"
          return 1
        }}''')
        if mode == 'open': retry = retry.replace('phase=LOCKED', 'phase=OPEN')
        outcome = run(issue=True, override=retry)
        assert outcome.startswith('0|') if success else outcome == '2|risk-provider-unavailable'
        assert len((root / 'retry-calls').read_text()) == expected_calls
        assert (root / 'runtime/risk-last-attempt').exists()
        assert run(issue=True, override=retry) == ('0|' + outcome.split('|')[1] + '|risk-unavailable' if success else '2|risk-rate-limited')
    for confidence in [0, 25, 89]:
        for flag in [False, True]:
            cache.unlink(missing_ok=True)
            (root / 'runtime/risk-last-attempt').write_text(str(int(time.time()) - 3601))
            (root / 'response').write_text(json.dumps(response(flag=flag, confidence=confidence)))
            outcome = run()
            assert outcome == '1' if flag else outcome.startswith('0|')
    # Exercise the real curl wrapper. A TLS handshake can fit inside a risk
    # request's four-second budget while exceeding the health-specific budget.
    # The fake transport checks deadlines without sleeping or using a network.
    curl = root / 'curl'
    curl.write_text('''#!/usr/bin/python3
from pathlib import Path
import sys
args = sys.argv[1:]
connect = float(args[args.index('--connect-timeout') + 1])
total = float(args[args.index('--max-time') + 1])
if min(connect, total) < 3:
    raise SystemExit(28)
Path(args[args.index('--output') + 1]).write_text('bounded-response')
print('200', end='')
''')
    curl.chmod(0o700)
    transport = source.replace('/usr/bin/curl', str(curl))
    def actual_transport(seconds):
        return subprocess.run(['/bin/sh', '-c', transport +
            f"\ndirectory='{root}/runtime'\niface=utun1\ntunnel_response {seconds} https://example.invalid\n"],
            capture_output=True, text=True)
    within = actual_transport(4)
    assert within.returncode == 0 and within.stdout == 'bounded-response'
    expired = actual_transport(2)
    assert expired.returncode != 0 and not expired.stdout
    assert not list((root / 'runtime').glob('probe.*'))
    print('PASS: keyless actual-worker admission, cache age, denied/missing facts, persistent quota spacing, confidence semantics and bounded TLS connect budget')
