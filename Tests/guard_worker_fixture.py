"""Exercise shell policy with a simulated PF, VPN and native-filter adapter.

The real cross-process native fence and power boundary have separate fixtures.
"""
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1] / "Sources" / "GuardWorker.sh"
assert sys.argv[1:] in ([], ['--cadence'], ['--cadence-baseline'])
CADENCE = bool(sys.argv[1:])

with tempfile.TemporaryDirectory(prefix="cg-worker-test-") as work:
    root = Path(work)
    runtime = root / "runtime"
    mock = root / "pfctl"
    mock.write_text("""#!/usr/bin/python3
from pathlib import Path
import sys,time
root = Path(__file__).parent
args = sys.argv[1:]
rules = root / 'rules'
if (root / 'cadence').exists() and '-sr' in args: time.sleep(.15)
if args == ['-sr']:
    print((root / 'main').read_text(), end='')
elif args == ['-s', 'info']:
    state = root / 'pf-status'
    print('Status: ' + (state.read_text().strip() if state.exists() else 'Enabled'))
elif args == ['-E']:
    (root / 'pf-status').write_text('Enabled')
    print('Token : 773')
elif args == ['-X', '773']:
    (root / 'released').touch()
elif args == ['-F', 'states']:
    (root / 'flushed').touch()
elif args[-2:] == ['-F', 'rules']:
    rules.write_text('')
elif args[-2:] == ['-f', '-']:
    incoming = sys.stdin.read()
    if '-n' not in args:
        rules.write_text(incoming)
        fault = root / 'inject-open-rule'
        if fault.exists() and 'CG_PROBE_OUT' in incoming:
            rules.write_text('pass quick all\\n' + incoming)
            fault.unlink()
    elif '-v' in args:
        print(incoming, end='')
elif args == ['-a', 'cisco.anyconnect.vpn', '-sr']:
    pass
elif args == ['-a', 'com.apple/00000.before-guard', '-sr']:
    if (root / 'earlier-rules').exists(): print((root / 'earlier-rules').read_text(), end='')
elif args[-1:] == ['-sr'] and args[1].startswith('com.apple/00000'):
    text = rules.read_text() if rules.exists() else ''
    if not text and (root / 'strict-empty').exists():
        sys.exit(1)
    print(text, end='')
elif args == ['-a', 'com.apple', '-s', 'Anchors']:
    if (root / 'earlier-anchor').exists(): print('com.apple/00000.before-guard')
elif args == ['-v', '-s', 'Interfaces']:
    if (root / 'skip-loopback').exists(): print('lo0 (skip)')
else:
    sys.exit(3)
""")
    mock.chmod(0o755)
    filter_helper = root / "filter-helper"
    filter_helper.write_text('''#!/usr/bin/python3
from pathlib import Path
import subprocess,sys,time
root=Path(__file__).parent
args=sys.argv[1:]
body=sys.stdin.buffer.read()
if (root/'cadence').exists() and args[:1]==['--filter-load'] and args[-1:] == ['OPEN']: time.sleep(1)
if args[0]=='--filter-adopt' and len(args)==2:
    known=root/'native-last-rules'
    actual=root/'rules'
    raise SystemExit(0 if known.exists() and actual.exists() and body.strip()==known.read_bytes().strip()==actual.read_bytes().strip() else 74)
if args[0]=='--filter-clear' and len(args)==2:
    command=['-a','com.apple/00000.org.claudeguard.runtime','-F','rules']
elif args[0]=='--filter-load' and len(args)==3 and args[2] in ('OPEN','LOCKED','SEALED'):
    command=['-a','com.apple/00000.org.claudeguard.runtime','-f','-']
else: raise SystemExit(64)
result=subprocess.run([str(root/'pfctl'),*command],input=body)
if result.returncode==0 and args[0]=='--filter-load': (root/'native-last-rules').write_bytes(body)
raise SystemExit(result.returncode)
''')
    filter_helper.chmod(0o700)
    service = "11111111-1111-1111-1111-111111111111"
    scutil = root / "scutil"
    scutil.write_text("""#!/usr/bin/python3
from pathlib import Path
import sys
root = Path(__file__).parent
args = sys.argv[1:]
service = (root / 'service').read_text().strip()
connection = (root / 'vpn').read_text().strip()
if args == ['--nc', 'list']:
    print('* (Connected) ' + service + ' VPN (com.liguangming.Shadowrocket) "Fixture" [VPN:com.liguangming.Shadowrocket]')
elif args == ['--nc', 'status', service]:
    if connection.startswith('utun'):
        print('Connected')
        print('Extended Status <dictionary> {')
        print('  IPv4 : <dictionary> {')
        print('    InterfaceName : ' + connection)
        print('  }')
        print('}')
    else:
        print(connection)
elif args == ['--nc', 'start', service]:
    (root / 'reconnect').touch()
elif args == ['--nc', 'stop', service]:
    with (root / 'recycled').open('a') as log:
        print(service, file=log)
    (root / 'vpn').write_text('Disconnected')
else:
    sys.exit(3)
""")
    scutil.chmod(0o755)
    (root / "service").write_text(service)
    (root / "vpn").write_text("utun6")
    clock = root / "date"
    clock.write_text("""#!/usr/bin/python3
from pathlib import Path
import time
offset = Path(__file__).with_name("clock-offset")
print(int(time.time()) + (int(offset.read_text()) if offset.exists() else 0))
""")
    clock.chmod(0o755)
    curl = root / "curl"
    curl.write_text("""#!/usr/bin/python3
from pathlib import Path
import os
import sys
root = Path(__file__).parent
args = sys.argv[1:]
assert args[0] == '-q' and args[args.index('--noproxy') + 1] == '*'
assert args[args.index('--interface') + 1].startswith('if!utun')
assert args[args.index('--proto') + 1] == '=https' and '--tlsv1.2' in args
assert args[args.index('--write-out') + 1] == '%{http_code}'
output = Path(args[args.index('--output') + 1])
relative = output.relative_to(root / 'runtime')
assert len(relative.parts) == 1 or (len(relative.parts) == 3 and relative.parts[0].startswith('health.') and relative.parts[1] in ('primary','backup'))
assert os.environ['HOME'] == '/var/empty'
assert not any(name in os.environ for name in ('CURL_HOME', 'CURL_CA_BUNDLE', 'HTTPS_PROXY'))
import json
if '--config' in args:
    if (root / 'cadence').exists():
        import time
        time.sleep(3)
    config = sys.stdin.read()
    assert 'FixtureRiskKey0123456789' not in ' '.join(args)
    assert 'IPQS-KEY: FixtureRiskKey0123456789' in config
    assert 'ip=192.0.2.42' in config
    reply = root / 'risk-response'
    output.write_text(reply.read_text() if reply.exists() else '{"decision": 0}')
    (root / 'risk-called').touch()
    fault = root / 'change-after-risk'
    if fault.exists():
        (root / 'route-1.1.1.1').write_text('interface: en0')
        fault.unlink()
    print('200', end='')
    sys.exit(0)
if 'cloudflare-dns.com:443:1.1.1.1' in args:
    assert '--resolve' in args
    invalid_dns = root / 'risk-dns'
    if invalid_dns.exists():
        output.write_text(invalid_dns.read_text())
        print('200', end='')
        sys.exit(0)
    output.write_text(json.dumps({'Status': 0, 'TC': False,
        'Question': [{'name': 'www.ipqualityscore.com', 'type': 1}],
        'Answer': [{'type': 1, 'data': '93.184.216.34'}]}))
    print('200', end='')
    sys.exit(0)
address = sys.argv[-1].split('/')[2]
assert address in ('1.1.1.1', '1.0.0.1')
name = 'primary' if address == '1.1.1.1' else 'backup'
with (root / 'probe-log').open('a') as log:
    print(name, file=log)
import fcntl
dropped = False
with (root / 'probe-control.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    jump = root / 'jump-during-probe'
    if jump.exists():
        clock = root / 'clock-offset'
        clock.write_text(str((int(clock.read_text()) if clock.exists() else 0) + int(jump.read_text())))
        jump.unlink()
    drop = root / 'drop-next'
    if drop.exists() and int(drop.read_text()) > 0:
        drop.write_text(str(int(drop.read_text()) - 1))
        dropped = True
if dropped:
    if (root / 'cadence').exists():
        import time
        time.sleep(4)
    sys.exit(28)
override = root / name
value = (override if override.exists() else root / 'exit').read_text().strip()
if value == '-':
    sys.exit(28)
code = 200
if value == 'duplicate':
    body = b'ip=192.0.2.42\\nip=192.0.2.99'
elif value == 'extra-equals':
    body = b'ip=192.0.2.42=garbage'
elif value == 'redirect':
    body = b'ip=192.0.2.42'
    code = 302
elif value == 'partial':
    output.write_bytes(b'ip=192.0.2.42')
    sys.exit(18)
elif value == 'nul':
    body = b'ip=192.0.2.' + bytes([0]) + b'42'
else:
    body = ('ip=' + value).encode()
output.write_bytes(body)
print(code, end='')
""")
    curl.chmod(0o755)
    route = root / "route"
    route.write_text("""#!/usr/bin/python3
from pathlib import Path
import sys
root = Path(__file__).parent
assert sys.argv[1:4] == ['-n', 'get', '-inet']
override = root / ('route-' + sys.argv[4])
if override.exists():
    print(override.read_text())
else:
    print('interface: ' + (root / 'vpn').read_text().strip())
""")
    route.chmod(0o755)
    netstat = root / "netstat"
    netstat.write_text("""#!/usr/bin/python3
from pathlib import Path
gateway = Path(__file__).with_name("gateway").read_text().strip()
print("Destination Gateway Flags Netif Expire")
print("default link#24 UCSg utun6")
print("default " + gateway + " UGScIg en0")
if Path(__file__).with_name("ethernet").exists():
    print("default 192.0.2.254 UGScIg en1")
""")
    netstat.chmod(0o755)
    (root / "gateway").write_text("192.0.2.1")
    ifconfig = root / "ifconfig"
    ifconfig.write_text("""#!/usr/bin/python3
from pathlib import Path
import sys
root = Path(__file__).parent
if sys.argv[1:] == ['-a']:
    print('en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>')
    print('    inet 192.0.2.30 netmask 0xffffff00')
    print('    status: ' + ('inactive' if (root / 'wifi-down').exists() else 'active'))
    if (root / 'ethernet').exists():
        print('en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>')
        print('    inet 192.0.2.31 netmask 0xffffff00')
        print('    status: active')
    print('utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>')
    print('    inet 198.51.100.3 netmask 0xffffff00')
elif sys.argv[1:] == ['utun7']:
    print('utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>')
    print('    inet 100.64.0.2 netmask 0xffffffff')
""")
    ifconfig.chmod(0o755)
    launchctl = root / "launchctl"
    launchctl.write_text("""#!/bin/sh
echo "$@" >> "$(dirname "$0")/launchctl-log"
""")
    launchctl.chmod(0o755)
    boot_dir = root / "boot"
    boot_plist = root / "org.claudeguard.guardian.plist"
    standard = 'anchor "com.apple/*" all\n'
    (root / "main").write_text('scrub-anchor "cisco.anyconnect.vpn" all fragment reassemble\nscrub-anchor "com.apple/*" all fragment reassemble\nanchor "cisco.anyconnect.vpn" all\n' + standard)
    (root / "exit").write_text("192.0.2.42\n")
    evaluator = root / "evaluator"
    evaluator.write_text("""#!/usr/bin/python3
import json
import sys
assert sys.argv[1:] == ['--validate-risk', 'US']
try:
    result = json.load(sys.stdin)['decision']
except (ValueError, KeyError):
    result = 2
sys.exit(result if result in (0, 1, 2) else 2)
""")
    evaluator.chmod(0o755)
    ipconfig = root / "ipconfig"
    ipconfig.write_text("#!/bin/sh\nexit 0\n")
    ipconfig.chmod(0o755)
    ps = root / "ps"
    ps.write_text("""#!/usr/bin/python3
import subprocess
import sys
result = subprocess.run(['/bin/ps', *sys.argv[1:]], capture_output=True, text=True)
if result.returncode == 0:
    parts = result.stdout.strip().split(maxsplit=1)
    if len(parts) == 2:
        print('0 ' + parts[1])
sys.exit(result.returncode)
""")
    ps.chmod(0o755)
    script = SOURCE.read_text().replace(
        "pf=/sbin/pfctl", "pf=" + str(mock)
    ).replace(
        "filter_helper=$boot_dir/GuardDaemon", "filter_helper=" + str(filter_helper)
    ).replace(
        "directory=/var/run/org.claudeguard.runtime", "directory=" + str(runtime)
    ).replace(
        '$(/usr/bin/id -u)', "0"
    ).replace(
        " = 0 ] || exit 78", " = " + str(os.getuid()) + " ] || exit 78"
    ).replace("/bin/ps", str(ps)).replace("/usr/sbin/ipconfig", str(ipconfig)).replace(
        "/Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon", str(evaluator)
    ).replace("/sbin/ifconfig", str(ifconfig)).replace("/usr/sbin/scutil", str(scutil)).replace("guard_sleep 5", "guard_sleep 1").replace("/bin/date", str(clock)).replace("/usr/bin/curl", str(curl)).replace("/usr/sbin/netstat", str(netstat)).replace("/sbin/route", str(route)).replace(
        "boot_dir=/Library/PrivilegedHelperTools/org.claudeguard", "boot_dir=" + str(boot_dir)
    ).replace(
        "boot_plist=/Library/LaunchDaemons/org.claudeguard.guardian.plist", "boot_plist=" + str(boot_plist)
    ).replace(
        "launchctl=/bin/launchctl", "launchctl=" + str(launchctl)
    ).replace(
        "chown_tool=/usr/sbin/chown", "chown_tool=/usr/bin/true"
    )
    session = str(uuid.uuid4())
    runtime.mkdir(mode=0o700)

    definitions = script.split('action=${1-}')[0]
    expired_wait = definitions + '''
phase=OPEN; last_verified=1
load_phase() { printf '%s|' "$1"; }
rules_intact() { exit 99; }
publish() { printf '%s' "$3"; }
guard_sleep 5
'''
    expired = subprocess.run(['/bin/sh', '-c', expired_wait], check=True,
                             capture_output=True, text=True, timeout=2)
    assert expired.stdout == 'LOCKED|evidence-expired'
    probe = definitions + '\niface=utun6\nif sample_exit; then printf "PASS:%s" "$observed"; else printf FAIL; fi\n'
    hostile = {**os.environ, 'CURL_HOME': str(root), 'CURL_CA_BUNDLE': str(root),
               'HTTPS_PROXY': 'http://127.0.0.1:9999'}
    assert subprocess.run(['/bin/sh', '-c', probe], check=True, capture_output=True,
                          text=True, env=hostile).stdout == 'PASS:192.0.2.42'
    for invalid_response in ('duplicate', 'extra-equals', 'redirect', 'partial', 'nul'):
        (root / 'primary').write_text(invalid_response)
        (root / 'backup').write_text(invalid_response)
        assert subprocess.run(['/bin/sh', '-c', probe], check=True, capture_output=True,
                              text=True, env=hostile).stdout == 'FAIL', invalid_response
        assert not list(runtime.glob('probe.*'))
    (root / 'primary').unlink()
    (root / 'backup').unlink()
    phase_check = definitions + '''
iface=utun6; peer=192.0.2.42; protocol=tcp; port=443; peer_ifaces=en0
if load_phase LOCKED; then printf VERIFIED; else printf REJECTED; fi
'''
    assert subprocess.run(['/bin/sh', '-c', phase_check], check=True, capture_output=True,
                          text=True).stdout == 'VERIFIED'
    (root / 'inject-open-rule').touch()
    assert subprocess.run(['/bin/sh', '-c', phase_check], check=True, capture_output=True,
                          text=True).stdout == 'REJECTED'
    assert 'pass quick all' not in (root / 'rules').read_text()
    assert 'CG_PROBE_OUT' not in (root / 'rules').read_text()
    (root / 'rules').write_text('')

    (root / 'earlier-anchor').touch()
    preflight_check = definitions + "\npreflight\n"
    assert subprocess.run(['/bin/sh', '-c', preflight_check], capture_output=True).returncode == 0
    (root / 'skip-loopback').touch()
    assert subprocess.run(['/bin/sh', '-c', preflight_check], capture_output=True).returncode != 0
    (root / 'skip-loopback').unlink()
    (root / 'earlier-rules').write_text('pass quick all\n')
    assert subprocess.run(['/bin/sh', '-c', preflight_check], capture_output=True).returncode != 0
    (root / 'earlier-rules').unlink()
    (root / 'earlier-anchor').unlink()
    risk_check = definitions + '''
iface=utun6; peer=192.0.2.42; protocol=tcp; port=443; peer_ifaces=en0
phase=LOCKED; observed=192.0.2.42; risk_region=US
risk_key=FixtureRiskKey0123456789
risk_evaluator=''' + str(evaluator) + '''
# This function-only fixture has no running worker/status publication context.
publish() { return 0; }
if review_exit_risk; then printf 0; else printf '%s' "$?"; fi
'''
    for decision in (0, 1, 2):
        (root / 'risk-response').write_text(json.dumps({'decision': decision}))
        result = subprocess.run(['/bin/sh', '-c', risk_check], check=True, capture_output=True, text=True)
        assert result.stdout == str(decision), result
        assert 'CG_RISK_OUT' not in (root / 'rules').read_text()
        assert 'FixtureRiskKey' not in (root / 'rules').read_text()
    (root / 'risk-response').unlink()
    (root / 'risk-dns').write_text(json.dumps({'Status': 0, 'TC': False,
        'Question': [{'name': 'www.ipqualityscore.com.', 'type': 1}],
        'Answer': [{'type': 1, 'data': '127.0.0.1'}]}))
    assert subprocess.run(['/bin/sh', '-c', risk_check], check=True, capture_output=True, text=True).stdout == '2'
    (root / 'risk-dns').unlink()
    (root / 'rules').write_text('')

    development_check = definitions + '''
iface=utun6; peer=192.0.2.42; protocol=tcp; port=443; peer_ifaces=en0
development_peer=100.64.0.3
development_binding=$(development_snapshot)
development_iface=${development_binding%%|*}
development_self=${development_binding#*|}
build_rules "$1"
'''
    (root / 'route-100.64.0.3').write_text('interface: utun7')
    for phase in ('OPEN', 'LOCKED', 'SEALED'):
        result = subprocess.run(['/bin/sh', '-c', development_check, 'fixture', phase], check=True, capture_output=True, text=True)
        assert ('CG_DEV_OUT' in result.stdout) == (phase == 'OPEN')
        if phase == 'OPEN':
            assert 'on utun7 inet proto tcp from 100.64.0.2 to 100.64.0.3 port = 22' in result.stdout
            subprocess.run(['/sbin/pfctl', '-n', '-a', 'com.apple/00000.org.claudeguard.runtime', '-f', '-'],
                           input=result.stdout, capture_output=True, text=True, check=True)
    (root / 'route-100.64.0.3').write_text('interface: en0')
    result = subprocess.run(['/bin/sh', '-c', development_check, 'fixture', 'OPEN'], check=True, capture_output=True, text=True)
    assert 'CG_DEV_OUT' not in result.stdout
    (root / 'route-100.64.0.3').unlink()

    def until(check, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.1)
        raise AssertionError(("condition not met", status()))

    def status():
        path = runtime / "status"
        return path.read_text().strip().split("|") if path.exists() else ["", ""]

    def expect(phase, timeout=20, reason=None, interface=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = status()
            if current[1] == phase and (reason is None or current[6] == reason) and (interface is None or current[3] == interface):
                return
            time.sleep(0.1)
        raise AssertionError((phase, status(), worker.poll(), worker.stderr.read() if worker.poll() is not None else "running"))

    def worker_process(command, **options):
        if len(command) > 4 and command[4] == 'worker':
            args = command[5:]
            identity, mode, interface, peer, transport, port, expected = args[:7]
            service_id = args[7] if len(args) > 7 else ''
            boot = args[8] if len(args) > 8 else 'run'
            admin = args[9] if len(args) > 9 else ''
            fields = [mode, interface, peer, transport, port, expected, 'US', service_id, boot, '0', admin, '']
            command = command[:4] + ['worker-input', identity]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, **options)
            process.stdin.write('FixtureRiskKey0123456789\n' + '|'.join(fields) + '\n' + str(evaluator) + '\n')
            process.stdin.close()
            process.stdin = None
            return process
        return subprocess.Popen(command, **options)

    if CADENCE:
        (root / 'cadence').touch()
        # Keep the production sleep ceiling. The usual accelerated fixture
        # cannot expose work accumulating across that production interval.
        script = script.replace('guard_sleep 1', 'guard_sleep 5')

    # Run one full production observation window before using scaled times
    # for the remaining state-machine fixtures.
    production = ["/bin/sh", "-c", script, "claude-guard-worker"]
    worker = worker_process(
        production + ["worker", session, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("LOCKED", reason="settling")
        assert status()[12] == "ipv4-tunnel-v9"
        first = int(status()[2])
        time.sleep(4)
        assert status()[1] == "LOCKED"
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        expect("OPEN", timeout=40)
        assert int(status()[2]) - first >= 15
        assert (root / "probe-log").read_text().count("primary") >= 6
        if CADENCE:
            if sys.argv[1:] == ['--cadence']:
                (root / 'drop-next').write_text('2')
            end = time.monotonic() + 30
            failure = None
            saw_retry = False
            while time.monotonic() < end:
                current = status()
                saw_retry |= current[1] == 'OPEN' and current[6] == 'probe-retry'
                if current[1] != 'OPEN':
                    failure = current[1] + ':' + current[6]
                    break
                time.sleep(.1)
            print('CADENCE_RESULT ' + (failure or 'continuous-open'), flush=True)
            if sys.argv[1:] == ['--cadence-baseline']:
                assert failure == 'LOCKED:revalidating', failure
            else:
                assert failure is None, failure
                assert saw_retry, 'Bounded empty health round was not exercised'
        subprocess.run(production + ["stop"], check=True, capture_output=True)
        expect("IDLE")
        assert not list(runtime.glob('health.*'))
    finally:
        if worker.poll() is None:
            worker.terminate()
        worker.communicate(timeout=8)

    if CADENCE:
        print('PASS: production cadence, bounded slow risk response and filter work without host changes')
        raise SystemExit(0)

    scaled = script.replace("stability_seconds=15", "stability_seconds=4").replace(
        "stability_samples=6", "stability_samples=4"
    ).replace("stability_tick=3", "stability_tick=1")
    prefix = ["/bin/sh", "-c", scaled, "claude-guard-worker"]
    session = str(uuid.uuid4())
    worker = worker_process(
        prefix + ["worker", session, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        assert (root / "flushed").exists()
        opened = (root / "rules").read_text()
        assert "on en0 inet proto tcp from any to 192.0.2.42 port = 443" in opened
        assert opened.index("CG_MCAST") < opened.index("CG_TUNNEL")
        runtime_journal = runtime / "events"
        prior_locks = runtime_journal.read_text().count("|LOCKED|")

        # A reachable backup covers a failed primary without interrupting existing traffic.
        (root / "primary").write_text("-")
        expect("OPEN", reason="probe-backup")
        assert "backup" in (root / "probe-log").read_text()
        assert "CG_TUNNEL" in (root / "rules").read_text()
        (root / "primary").unlink()
        expect("OPEN", reason="probe-ok")

        # One whole failed round should be visible but should not load a locked ruleset.
        (root / "drop-next").write_text("2")
        expect("OPEN", reason="probe-retry")
        assert "CG_TUNNEL" in (root / "rules").read_text()
        expect("OPEN", reason="probe-ok")
        assert runtime_journal.read_text().count("|LOCKED|") == prior_locks

        # A forced-interface probe must not mask a different route for ordinary traffic.
        health_route = root / 'route-1.0.0.1'
        health_route.write_text('interface: en0')
        expect('LOCKED', reason='route-mismatch')
        assert 'CG_TUNNEL' not in (root / 'rules').read_text()
        assert 'CG_PROBE_OUT' not in (root / 'rules').read_text()
        health_route.write_text('interface: utun6\ninterface: en0')
        expect('LOCKED', reason='route-unknown')
        health_route.unlink()
        expect('LOCKED', reason='settling')
        expect('OPEN')

        # A readback that contains the expected labels plus an unknown pass
        # must not become the integrity baseline.
        (root / 'inject-open-rule').touch()
        (root / 'gateway').write_text('192.0.2.8')
        expect('DRIFT')
        assert 'CG_TUNNEL' not in (root / 'rules').read_text()
        assert 'pass quick all' not in (root / 'rules').read_text()
        expect('OPEN')

        # An elapsed lease during a request requires a new dwell, even if the reply matches.
        (root / 'jump-during-probe').write_text('20')
        expect('LOCKED', reason='evidence-expired')
        assert 'CG_TUNNEL' not in (root / 'rules').read_text()
        expect('OPEN')

        # Sustained failure closes the tunnel after the one bounded retry round.
        (root / "primary").write_text("-")
        (root / "backup").write_text("-")
        expect("OPEN", reason="probe-retry")
        expect("LOCKED", reason="probe-failed")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "primary").unlink()
        (root / "backup").unlink()
        expect("OPEN")

        # Unrelated reachability must never renew exit identity evidence.
        prior_degraded = runtime_journal.read_text().count("probe-degraded")
        (root / "primary").write_text("-")
        (root / "backup").write_text("-")
        expect("OPEN", reason="probe-retry")
        expect("LOCKED", reason="probe-failed")
        assert runtime_journal.read_text().count("probe-degraded") == prior_degraded
        (root / "primary").unlink()
        (root / "backup").unlink()
        expect("OPEN")

        # A wrong IP is not a timeout. A working backup must not overrule it.
        (root / "primary").write_text("192.0.2.99")
        expect("LOCKED", reason="exit-mismatch")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "primary").unlink()
        expect("OPEN")

        # A valid primary cannot hide a different exit from the concurrent backup.
        (root / "backup").write_text("192.0.2.99")
        expect("LOCKED", reason="exit-mismatch")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "backup").unlink()
        expect("OPEN")

        # Even without a VPN disconnect or utun change, switching the visible
        # route must invalidate the open state and restart the timer.
        (root / "gateway").write_text("192.0.2.2")
        expect("LOCKED", reason="settling")
        assert "route-changed" in runtime_journal.read_text()
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "drop-next").write_text("2")
        expect("LOCKED", reason="probe-failed")
        expect("LOCKED", reason="settling")

        # A sleep/scheduling or clock gap must not satisfy the dwell gate.
        (root / "clock-offset").write_text("20")
        time.sleep(2)
        assert status()[1] == "LOCKED"
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        expect("OPEN")

        # Loss of the Wi-Fi link must seal even while its route and the VPN status linger.
        (root / "wifi-down").touch()
        expect("LOCKED", reason="underlay-offline")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        assert "CG_PROBE_OUT" not in (root / "rules").read_text()
        assert "CG_PEER_OUT" not in (root / "rules").read_text()
        before = (root / "probe-log").read_text()
        time.sleep(1.4)
        assert (root / "probe-log").read_text() == before
        assert not (root / "reconnect").exists()

        # Local recovery with a stale Connected status requires one recycle and a new dwell.
        (root / "exit").write_text("-")
        (root / "wifi-down").unlink()
        expect("LOCKED", reason="vpn-restarting")
        expect("LOCKED", reason="vpn-reconnect")
        assert (root / "recycled").read_text().splitlines() == [service]
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "exit").write_text("192.0.2.42")
        (root / "vpn").write_text("utun6")
        expect("LOCKED", reason="settling")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        expect("OPEN")

        # A usable Ethernet default route replaces Wi-Fi and requires a fresh dwell.
        (root / "ethernet").touch()
        (root / "wifi-down").touch()
        expect("LOCKED", reason="settling")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        assert "on en1 inet proto tcp" in (root / "rules").read_text()
        assert "on en0 inet proto tcp" not in (root / "rules").read_text()
        expect("OPEN")
        (root / "ethernet").unlink()
        (root / "wifi-down").unlink()
        expect("OPEN")

        (root / "vpn").write_text("Disconnected")
        expect("LOCKED", reason="vpn-reconnect")
        assert (root / "reconnect").exists()
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        assert "CG_PROBE_OUT" not in (root / "rules").read_text()
        (root / "vpn").write_text("utun9")
        expect("OPEN", interface="utun9")
        assert "on utun9 inet all" in (root / "rules").read_text()
        (root / "service").write_text("22222222-2222-2222-2222-222222222222")
        expect("LOCKED", reason="vpn-wait")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "service").write_text(service)
        expect("OPEN", interface="utun9")
        (root / "main").write_text("pass all\n" + standard)
        expect("DRIFT")
        time.sleep(3)
        assert status()[1] == "DRIFT"
        assert "CG_TUNNEL" not in (root / "rules").read_text()

        # Once the foreign rule is gone, state is cleared and the tunnel is revalidated.
        (root / "flushed").unlink()
        (root / "main").write_text(standard)
        until(lambda: (root / "flushed").exists())
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        expect("OPEN")
        subprocess.run(prefix + ["stop"], check=True, capture_output=True)
        expect("IDLE")
        assert (root / "rules").read_text() == ""
        assert (root / "released").exists()
        assert not (runtime / "active").exists()
        journal = (runtime / "events").read_text()
        for phase in ["|OPEN|", "|LOCKED|", "|DRIFT|", "|IDLE|"]:
            assert phase in journal
    finally:
        if worker.poll() is None:
            worker.terminate()
        worker.communicate(timeout=8)

    (root / "vpn").write_text("utun6")
    (root / "main").write_text(standard)

    # Third-party interference must re-establish the block, not only report it.
    tampered = str(uuid.uuid4())
    worker = worker_process(
        prefix + ["worker", tampered, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        (root / "flushed").unlink()
        (root / "rules").write_text("")
        expect("DRIFT")
        until(lambda: "CG_BLOCK" in (root / "rules").read_text())
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        assert (root / "flushed").exists()

        (root / "pf-status").write_text("Disabled")
        until(lambda: (root / "pf-status").read_text() == "Enabled")
        assert "CG_BLOCK" in (root / "rules").read_text()
        expect("OPEN")

        # PF may discard the emptied anchor, so the query after a flush can fail.
        (root / "strict-empty").touch()
        subprocess.run(prefix + ["stop"], check=True, capture_output=True)
        expect("IDLE")
        assert (root / "rules").read_text() == ""
        assert not (runtime / "active").exists()
    finally:
        (root / "strict-empty").unlink(missing_ok=True)
        if worker.poll() is None:
            worker.terminate()
        worker.communicate(timeout=12)

    # An unconfirmed trial restores the network instead of stranding the Mac.
    expired = str(uuid.uuid4())
    worker = worker_process(
        prefix + ["worker", expired, "trial", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        (root / "clock-offset").write_text("90")
        expect("IDLE", reason="trial-ended")
        assert (root / "rules").read_text() == ""
        assert not (runtime / "active").exists()
    finally:
        if worker.poll() is None:
            worker.terminate()
        worker.communicate(timeout=12)

    trial = str(uuid.uuid4())
    worker = worker_process(
        prefix + ["worker", trial, "trial", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        subprocess.run(prefix + ["continue"], check=True, capture_output=True)
        until(lambda: status()[8] == "live" and status()[1] == "OPEN")

        # An ordinary signal without an explicit offline restore must not clear PF.
        (root / "released").unlink(missing_ok=True)
        worker.terminate()
        worker.communicate(timeout=8)
        expect("ERROR", reason="worker-stopped")
        assert not (root / "released").exists()
        assert "CG_BLOCK" in (root / "rules").read_text()
        assert "CG_TUNNEL" not in (root / "rules").read_text()

        # A separate recovery process can restore after the worker has died.
        subprocess.run(prefix + ["stop"], check=True, capture_output=True)
        expect("IDLE")
        assert (root / "rules").read_text() == ""
        assert (root / "released").exists()
        assert not (runtime / "active").exists()
    finally:
        if worker.poll() is None:
            worker.terminate()
            worker.communicate(timeout=8)

    (root / "service").write_text("22222222-2222-2222-2222-222222222222")
    rejected = subprocess.run(
        prefix + ["worker", str(uuid.uuid4()), "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42", service],
        capture_output=True,
    )
    assert rejected.returncode == 86
    assert status()[1] == "ERROR" and status()[6] == "tunnel-unverified"
    assert not (runtime / "active").exists()
    (root / "service").write_text(service)
    (root / "vpn").write_text("Disconnected")
    resumed = str(uuid.uuid4())
    worker = worker_process(
        prefix + ["worker", resumed, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42", service],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("LOCKED")
        assert status()[0] == resumed and status()[10] == service
        assert "CG_PROBE_OUT" not in (root / "rules").read_text()
        (root / "vpn").write_text("utun10")
        expect("OPEN", interface="utun10")
        subprocess.run(prefix + ["stop"], check=True, capture_output=True)
        expect("IDLE")
    finally:
        if worker.poll() is None:
            worker.terminate()
            worker.communicate(timeout=8)

    # A pinned boot route seals before the VPN is available, without a GUI.
    (root / "vpn").write_text("Disconnected")
    (root / "main").write_text("")
    (root / "pf-status").write_text("Disabled")
    boot = worker_process(
        prefix + ["worker", str(uuid.uuid4()), "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42", service, "boot"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        until(lambda: "CG_BLOCK" in (root / "rules").read_text())
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        until(lambda: (root / "pf-status").read_text() == "Enabled")
        (root / "main").write_text(standard)
        expect("LOCKED")
        (root / "vpn").write_text("utun6")
        expect("OPEN")
        subprocess.run(prefix + ["stop"], check=True, capture_output=True)
        expect("IDLE")
    finally:
        if boot.poll() is None:
            boot.terminate()
        boot.communicate(timeout=12)

    # Native startup seals before any shell marker exists. Exact native
    # ownership permits first-start adoption; foreign rules remain rejected.
    seal = 'block drop quick all label "CG_BLOCK"\n'
    assert not (runtime / 'active').exists()
    (root / 'rules').write_text(seal)
    (root / 'native-last-rules').write_text(seal)
    worker = worker_process(
        prefix + ['worker', str(uuid.uuid4()), 'live', 'utun6', '192.0.2.42', 'tcp', '443', '192.0.2.42', service],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        expect('OPEN')
        subprocess.run(prefix + ['stop'], check=True, capture_output=True)
        expect('IDLE')
    finally:
        if worker.poll() is None: worker.terminate()
        worker.communicate(timeout=12)
    foreign = 'pass quick all\nblock drop quick all label "CG_BLOCK"\n'
    (root / 'rules').write_text(foreign)
    (root / 'native-last-rules').write_text(seal)
    rejected = worker_process(
        prefix + ['worker', str(uuid.uuid4()), 'live', 'utun6', '192.0.2.42', 'tcp', '443', '192.0.2.42', service],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    rejected.communicate(timeout=12)
    assert rejected.returncode == 85 and (root / 'rules').read_text() == foreign

    # Native pre-sleep sealing changes PF outside the old shell's rule records.
    # Adoption must ask the native boundary; matching a generic block label is
    # insufficient, and arbitrary foreign rules must still fail closed.
    def retained_worker_marker():
        active = runtime / 'active'
        active.mkdir(mode=0o700)
        for name, value in [('pid', '99999999'), ('token', '773'), ('session', str(uuid.uuid4())),
                            ('last_rules', 'old shell rules'), ('next_rules', 'old pending rules')]:
            (active / name).write_text(value)
        return active
    retained_worker_marker()
    (root / 'rules').write_text(seal)
    (root / 'native-last-rules').write_text(seal)
    worker = worker_process(
        prefix + ['worker', str(uuid.uuid4()), 'live', 'utun6', '192.0.2.42', 'tcp', '443', '192.0.2.42', service],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        expect('OPEN')
        subprocess.run(prefix + ['stop'], check=True, capture_output=True)
        expect('IDLE')
    finally:
        if worker.poll() is None: worker.terminate()
        worker.communicate(timeout=12)
    active = retained_worker_marker()
    foreign = 'pass quick all\nblock drop quick all label "CG_BLOCK"\n'
    (root / 'rules').write_text(foreign)
    (root / 'native-last-rules').write_text(seal)
    rejected = worker_process(
        prefix + ['worker', str(uuid.uuid4()), 'live', 'utun6', '192.0.2.42', 'tcp', '443', '192.0.2.42', service],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    rejected.communicate(timeout=12)
    assert rejected.returncode == 85 and (root / 'rules').read_text() == foreign

print("PASS: stdin-only worker admission, risk gate, strict HTTPS parsing, hostile environment, scoped routes, expiring evidence, dwell, backup, bounded grace, network changes, Wi-Fi recovery, service binding, tamper repair, trial restoration, pinned boot recovery, first-start/retained native-seal adoption and foreign-rule rejection")
