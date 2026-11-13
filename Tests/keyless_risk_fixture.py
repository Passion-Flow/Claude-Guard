"""Exercise actual typed risk, renewal, cache and durable budgets without networking."""
from pathlib import Path
import json
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="cg-keyless-") as temporary:
    root = Path(temporary)
    runtime = root / "runtime"
    boot = root / "boot"
    runtime.mkdir(mode=0o700)
    boot.mkdir(mode=0o700)
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
    prefix = f"""
directory='{runtime}'; boot_dir='{boot}'
risk_evaluator='{evaluator}'; risk_key=
observed=192.0.2.42; expected=192.0.2.42; observed_region=US; risk_region=US
phase=LOCKED
publish() {{ return 0; }}
load_phase() {{ return 0; }}
resolve_risk_api() {{ printf 93.184.216.34; }}
tunnel_response() {{ printf x >> '{root}/calls'; cat '{root}/response'; }}
"""
    def shell(body, override=''):
        result = subprocess.run(['/bin/sh', '-c', source + prefix + override + '\n' + body],
                                capture_output=True, text=True, timeout=12)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        return result.stdout
    def review(override=''):
        return shell('if review_exit_risk; then printf "0|%s" "$risk_admission_at"; else printf "%s|%s" "$?" "$risk_issue"; fi', override)
    def response(flag=False, confidence=100):
        return {'status': 'ok', '192.0.2.42': {'network': {'type': 'Residential'}, 'detections': {
            'proxy': flag, 'vpn': False, 'tor': False, 'hosting': False, 'anonymous': False,
            'compromised': False, 'scraper': False, 'risk': 0, 'confidence': confidence},
            'last_updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}}
    def reset():
        for path in runtime.iterdir():
            assert path.is_file(), path.name
            path.unlink()
        (boot / 'risk-query-budget').unlink(missing_ok=True)
        (root / 'calls').write_text('')
        (root / 'response').write_text(json.dumps(response()))
    def unthrottle():
        stamp = str(int(time.time()) - 4000)
        (runtime / 'risk-last-attempt').write_text(stamp)
        (runtime / 'risk-last-refresh').write_text(stamp)
    def cached(age, value=None):
        (runtime / 'risk-cache').write_text(str(int(time.time()) - age) + '|192.0.2.42|US\n' + json.dumps(value or response()))
    def calls():
        return len((root / 'calls').read_text())
    reset()
    first = review()
    assert first.startswith('0|'), first
    assert review() == first and calls() == 1
    assert (boot / 'risk-query-budget').stat().st_mode & 0o777 == 0o600
    cached(2690)
    assert review('phase=OPEN\n').startswith('0|') and calls() == 1
    cached(2710)
    unthrottle()
    renewed = review('phase=OPEN\n')
    assert renewed.startswith('0|') and int(renewed.split('|')[1]) >= int(time.time()) - 5 and calls() == 2
    cached(3500)
    before = (runtime / 'risk-cache').read_text().split('|')[0]
    assert review() == '0|' + before and calls() == 2
    assert review('phase=OPEN\n') == '2|risk-rate-limited' and calls() == 2
    reset()
    cached(3601)
    (runtime / 'risk-last-attempt').write_text(str(int(time.time())))
    assert review() == '2|risk-rate-limited'
    unthrottle()
    (root / 'response').write_text(json.dumps(response(flag=True)))
    assert review().startswith('1|')
    denial = (runtime / 'risk-cache').read_text()
    assert review().startswith('1|') and review('phase=OPEN\n').startswith('1|') and calls() == 1
    assert (runtime / 'risk-cache').read_text() == denial
    reset()
    cached(2710)
    unthrottle()
    (root / 'response').write_text('{"status":"ok"}')
    assert review('phase=OPEN\n') == '2|risk-invalid-response'
    assert not (runtime / 'risk-cache').exists()
    assert review() == '2|risk-rate-limited'
    reset()
    cached(2710)
    unthrottle()
    no_dns = 'phase=OPEN\nresolve_risk_api() { return 1; }\n'
    assert review(no_dns) == '2|risk-dns-unavailable'
    original = (runtime / 'risk-cache').read_text()
    assert review(no_dns) == '2|risk-rate-limited'
    assert (runtime / 'risk-cache').read_text() == original and calls() == 0
    for mode, expected_calls, success in [('transient', 2, True), ('quota', 1, False), ('open', 1, False)]:
        reset()
        unthrottle()
        retry = f"""
tunnel_response() {{
  printf x >> '{root}/calls'
  count=$(/usr/bin/wc -c < '{root}/calls' | /usr/bin/tr -d ' ')
  if [ '{mode}' = transient ] && [ "$count" -ge 2 ]; then /bin/cat '{root}/response'; return 0; fi
  printf '%s' {'429' if mode == 'quota' else '000'} > "$directory/transport-status"
  return 1
}}
"""
        if mode == 'open': retry += 'phase=OPEN\n'
        outcome = review(retry)
        assert outcome.startswith('0|') if success else outcome == ('2|risk-rate-limited' if mode == 'quota' else '2|risk-provider-unavailable'), outcome
        assert calls() == expected_calls
        assert int((boot / 'risk-query-budget').read_text().split('|')[1]) == expected_calls
        again = review(retry)
        assert again.startswith('0|') if success else again == '2|risk-rate-limited'
        assert (runtime / 'risk-last-attempt').exists() == (mode != 'open')
    reset()
    cached(2710)
    unthrottle()
    assert review('phase=OPEN\ntunnel_response() { printf 200 > "$directory/transport-status"; return 1; }\n') == '2|risk-invalid-response'
    assert not (runtime / 'risk-cache').exists()
    reset()
    today = time.strftime('%Y%m%d', time.gmtime())
    ledger = boot / 'risk-query-budget'
    ledger.write_text(today + '|47\n')
    charge = 'if risk_charge_connection; then printf charged; else printf "%s" "$risk_issue"; fi'
    assert shell(charge) == 'charged'
    assert shell(charge) == 'risk-query-budget'
    assert ledger.read_text() == today + '|48\n'
    yesterday = time.strftime('%Y%m%d', time.gmtime(time.time() - 86400))
    ledger.write_text(yesterday + '|48\n')
    assert shell(charge) == 'charged' and ledger.read_text() == today + '|1\n'
    tomorrow = time.strftime('%Y%m%d', time.gmtime(time.time() + 86400))
    for invalid in [tomorrow + '|1', today + '|08', today + '|49', today + '|1\n' + today + '|1', 'invalid']:
        ledger.write_text(invalid)
        assert shell(charge) == 'risk-invalid-state'
        assert ledger.read_text() == invalid
    # Actual renewal control flow; substitute provider outcomes and OS facts.
    now = int(time.time())
    parent = f"""
session=fixture; vpn_service=service; iface=utun1; endpoint_key=fixture; bound_path=fixture
phase=OPEN; desired=OPEN; reason=probe-ok; last_probe={now}; last_verified={now - 1}
risk_checked_at={now - 2710}
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
underlay_snapshot() {{ printf fixture; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
sample_exit() {{ printf unexpected-probe; exit 90; }}
"""
    show = 'renew_risk_evidence; printf "%s|%s|%s|%s" "$desired" "$reason" "$risk_checked_at" "$last_verified"'
    for issue in ['risk-dns-unavailable', 'risk-provider-unavailable', 'risk-rate-limited', 'risk-query-budget']:
        verdict = f'\nreview_exit_risk() {{ risk_issue={issue}; return 2; }}\n'
        result = shell(show, parent + verdict).split('|')
        assert result == ['OPEN', 'risk-refresh-pending', str(now - 2710), str(now - 1)], result
        expired = shell(show, parent + f'\nrisk_checked_at={now - 3600}\n' + verdict)
        assert expired.startswith('LOCKED|') and expired.endswith('|0|0'), expired
    assert shell(show, parent + '\nreview_exit_risk() { return 1; }\n') == 'LOCKED|risk-rejected|0|0'
    assert shell(show, parent + '\nreview_exit_risk() { risk_issue=risk-invalid-response; return 2; }\n') == 'LOCKED|risk-invalid-response|0|0'
    success = f'\nreview_exit_risk() {{ risk_admission_at={now}; return 0; }}\n'
    assert shell(show, parent + success).startswith('OPEN|probe-ok|' + str(now))
    assert shell(show, parent + f'\nlast_verified={now - 13}\n' + success) == 'LOCKED|evidence-expired|0|0'
    long_locked = parent + f"""
phase=LOCKED
last_verified={now - 9}
sample_exit() {{ observed=192.0.2.42; observed_region=US; probe_observed_at={now}; return 0; }}
""" + success
    assert shell(show, long_locked) == f'LOCKED|settling|{now}|{now}'
    cadence = """
session=fixture; vpn_service=service; iface=utun1; endpoint_key=fixture; bound_path=fixture
risk_checked_at=1000
risk_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path|$risk_region"
if risk_review_due 3699; then exit 10; fi
risk_review_due 3700 || exit 11
risk_review_due 4600 || exit 12
risk_review_due 999 || exit 13
bound_path=changed
risk_review_due 2000 || exit 14
"""
    shell(cadence)
    for confidence in [0, 25, 89]:
        for flag in [False, True]:
            reset()
            (root / 'response').write_text(json.dumps(response(flag=flag, confidence=confidence)))
            outcome = review()
            assert outcome.startswith('1|') if flag else outcome.startswith('0|'), outcome
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
    print('PASS: actual risk/cache/renewal, negative persistence, original expiry, identity separation, restart spacing, UTC budget and bounded TLS')
