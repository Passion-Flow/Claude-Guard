"""Run the actual control/state code with a disposable, unprivileged worker.

Only fixed filesystem paths and UID ownership checks are translated in copied
sources. No launchd job, system rule, interface or installed helper is touched.
The worker models status/exit lifecycle; network enforcement has its own fixture.
"""
import base64
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPOSITORY = Path(__file__).resolve().parents[1]
assert sys.argv[1:] in ([], ['--migration'], ['--clock'], ['--clock-baseline'], ['--clock-heartbeat-baseline'], ['--restart'], ['--restart-baseline'], ['--restart-stale'], ['--restart-stale-baseline'], ['--observation'], ['--observation-baseline'], ['--admitting'], ['--admitting-baseline'])
MIGRATION_FIXTURE = sys.argv[1:] == ['--migration']
CLOCK_FIXTURE = sys.argv[1:] in (['--clock'], ['--clock-baseline'], ['--clock-heartbeat-baseline'])
RESTART_FIXTURE = sys.argv[1:] in (['--restart'], ['--restart-baseline'], ['--restart-stale'], ['--restart-stale-baseline'])
OBSERVATION_FIXTURE = sys.argv[1:] in (['--observation'], ['--observation-baseline'], ['--admitting'], ['--admitting-baseline'])

with tempfile.TemporaryDirectory(prefix="cg-core-test-") as work:
    root = Path(work)
    (root / "runtime").mkdir(mode=0o700)
    (root / "install").mkdir(mode=0o755)
    launchctl = root / "launchctl"
    launchctl.write_text('''#!/usr/bin/python3
from pathlib import Path
import os,signal,sys
root=Path(__file__).parent
assert sys.argv[1] in ('bootout','print','bootstrap')
if sys.argv[1]=='bootout':
    pid=root/'lock-holder.pid'
    if pid.exists():
        try: os.kill(int(pid.read_text()),signal.SIGKILL)
        except ProcessLookupError: pass
    (root/'primary-stopped').touch()
if sys.argv[1]=='print': sys.exit(113)
''')
    launchctl.chmod(0o755)
    pf = root / "pfctl"
    pf.write_text('''#!/usr/bin/python3
from pathlib import Path
import sys
root=Path(__file__).parent
args=sys.argv[1:]
rules=root/'native-rules'
if '-f' in args:
    body=sys.stdin.read().strip()
    if '-n' in args:
        failure=root/'fail-test-seal-parse'
        if 'CG_TUNNEL' not in body and failure.exists():
            failure.unlink()
            raise SystemExit(1)
        print(body)
    else: rules.write_text(body)
elif '-sr' in args:
    failure=root/'fail-test-open-readback'
    if rules.exists() and 'CG_TUNNEL' in rules.read_text() and failure.exists():
        failure.unlink()
        raise SystemExit(1)
    print(rules.read_text() if rules.exists() else '')
elif args==['-F','states']: pass
elif args==['-s','info']: print('Status: Enabled')
else: raise SystemExit(64)
''')
    pf.chmod(0o700)
    worker = r'''set -eu
umask 077
directory=FIXTURE_DIRECTORY
publish() {
  if [ -f "$directory/../pause-test-heartbeat" ]; then return; fi
  if [ -f "$directory/../pause-test-publication" ]; then return; fi
  stamp=$(/bin/date +%s)
  if [ ! -f "$directory/../pause-test-proof" ]; then observation=$stamp; fi
  proof_phase=$phase; status_phase=$phase
  if [ -f "$directory/../prepare-test-admission" ]; then proof_phase=ADMITTING; status_phase=LOCKED; fi
  printf '1|%s|%s|%s|%s|%s|%s|11111111-1111-1111-1111-111111111111|%s:%s/%s|%s|1\n' "$session" "$proof_phase" "$stamp" "${observation:-$stamp}" "$stamp" "$iface" "$peer" "$port" "$transport" "$expected" > "$directory/evidence.tmp"
  /bin/mv -f "$directory/evidence.tmp" "$directory/evidence"
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|1|11111111-1111-1111-1111-111111111111|%s:%s/%s|ipv4-tunnel-v9|%s\n' "$session" "$status_phase" "$stamp" "$iface" "$expected" "$expected" "$reason" "$deadline" "$mode" "$peer" "$port" "$transport" "$stamp" > "$directory/status"
}
if [ "$1" = stop ]; then
  if [ -d "$directory/active" ]; then
    session=$(/bin/cat "$directory/active/session")
    pid=$(/bin/cat "$directory/active/pid")
    : > "$directory/restore-$session"
    /bin/kill -TERM "$pid" 2>/dev/null || true
    count=0
    while [ -d "$directory/active" ] && [ "$count" -lt 100 ]; do
      /bin/kill -0 "$pid" 2>/dev/null || break
      /bin/sleep 0.03
      count=$((count+1))
    done
    /bin/rm -rf "$directory/active"
  fi
  printf CLEAR > "$directory/rules"
  exit 0
fi
if [ "$1" = continue ]; then
  session=$(/bin/cat "$directory/active/session")
  : > "$directory/continue-$session"
  exit 0
fi
[ "$1" = worker-input ] || exit 64
session=$2
IFS= read -r key
IFS='|' read -r mode iface peer transport port expected region service boot deadline admin development
IFS= read -r evaluator
/bin/mkdir -p -m 0700 "$directory/active"
printf '%s\n' "$$" > "$directory/active/pid"
printf '%s\n' "$session" > "$directory/active/session"
finish() {
  trap - TERM EXIT
  if [ -f "$directory/restore-$session" ]; then
    /bin/rm -rf "$directory/active"
    /bin/rm -f "$directory/restore-$session"
    phase=IDLE; reason=stopped
    printf CLEAR > "$directory/rules"
  else
    phase=ERROR; reason=worker-stopped
    printf SEALED > "$directory/rules"
  fi
  publish
  exit 0
}
trap finish TERM EXIT
while :; do
  phase=OPEN; reason=stable-open
  if [ "$mode" = sealed ]; then phase=LOCKED; reason=manual-paused; fi
  if [ -f "$directory/continue-$session" ]; then mode=live; deadline=0; fi
  printf '%s' "$phase" > "$directory/rules"
  publish
  /bin/sleep 0.1
done
'''.replace("FIXTURE_DIRECTORY", shlex.quote(str(root / "runtime")))
    if CLOCK_FIXTURE:
        clock = root / 'date'
        clock.write_text('''#!/usr/bin/python3
from pathlib import Path
import time
path=Path(__file__).with_name('clock-offset')
print(int(time.time()+(float(path.read_text()) if path.exists() else 0)))
''')
        clock.chmod(0o700)
        worker = worker.replace('/bin/date', str(clock))
    encoded = base64.b64encode(worker.encode()).decode()
    (root / "FixtureSource.swift").write_text(
        'import Foundation\nlet privilegedWorker = String(decoding: Data(base64Encoded: "' + encoded + '")!, as: UTF8.self)\nlet guardSigningTeam = ""\n')
    # Trust is supplied locally. The separately signed XPC fixture tests code hashes.
    (root / "FixtureTrust.swift").write_text('''import Darwin
import Foundation
struct GuardianTrust {
    static let directory = ''' + '"' + str(root / "install") + '"' + '''
    let ownerUID: UInt32
    static var ownerOverride: UInt32?
    static func load() -> Self? { Self(ownerUID: ownerOverride ?? getuid()) }
    func requirement(_ identifier: String) -> String? { nil }
}
''')
    inputs = ["NodeAdmission.swift", "GuardRiskPolicy.swift", "GuardService.swift", "GuardianStore.swift"]
    sources = []
    for name in inputs:
        text = (REPOSITORY / "Sources" / name).read_text()
        if name == "GuardianStore.swift":
            text = text.replace("geteuid() == 0", "geteuid() == getuid()")
            text = text.replace("owner: 0)", "owner: getuid())")
        path = root / name
        path.write_text(text)
        sources.append(str(path))
    core = (REPOSITORY / "Daemon/GuardianCore.swift").read_text()
    if sys.argv[1:] in (['--observation-baseline'], ['--admitting-baseline']):
        core = Path(os.environ['GUARD_CORE_BASELINE']).read_text()
    if CLOCK_FIXTURE:
        # Only the copied Core's wall clock changes. The actual host clock,
        # installed service and all system processes remain untouched.
        core = core.replace('Date()', 'FixtureWall.now()')
    if RESTART_FIXTURE:
        import json
        original = 'process.executableURL = URL(fileURLWithPath: "/bin/sh")'
        injected = 'process.executableURL = URL(fileURLWithPath: FileManager.default.fileExists(atPath: ' + json.dumps(str(root / 'fail-test-launch')) + ') ? ' + json.dumps(str(root / 'missing-test-shell')) + ' : "/bin/sh")'
        assert core.count(original) == 2
        core = core.replace(original, injected, 1)
    core = core.replace('"/var/run/org.claudeguard.runtime"', '"' + str(root / "runtime") + '"')
    core = core.replace("metadata.st_uid == 0", "metadata.st_uid == getuid()")
    core = core.replace('whereSeparator: \\.isWhitespace).first == "0"',
                        'whereSeparator: \\.isWhitespace).first.map(String.init) == String(getuid())')
    (root / "GuardianCore.swift").write_text(core)
    coordinator = (REPOSITORY / "Daemon/GuardianRecovery.swift").read_text().replace('/bin/launchctl', str(launchctl))
    (root / "GuardianRecovery.swift").write_text(coordinator)
    sources += [str(root / "GuardianCore.swift"), str(root / "FixtureSource.swift"), str(root / "FixtureTrust.swift"),
                str(root / "GuardianRecovery.swift"),
                str(REPOSITORY / "Daemon/GuardianPacketFence.swift"),
                str(REPOSITORY / "Daemon/GuardianObservationLease.swift"),
                str(REPOSITORY / "Daemon/GuardianPowerObserver.swift"),
                str(REPOSITORY / "Tests" / ("guardian_observation_fixture.swift" if OBSERVATION_FIXTURE else ("guardian_migration_fixture.swift" if MIGRATION_FIXTURE else ("guardian_restart_fixture.swift" if RESTART_FIXTURE else ("guardian_clock_fixture.swift" if CLOCK_FIXTURE else "guardian_core_fixture.swift")))))]
    if MIGRATION_FIXTURE:
        sources += [str(REPOSITORY / "Sources/ShadowrocketProfile.swift"),
                    str(REPOSITORY / "Sources/AutomaticDiscovery.swift")]
    executable = root / "CoreFixture"
    try:
        subprocess.run(["swiftc", "-swift-version", "5", "-O", "-D", "GUARD_DIAGNOSTICS", "-parse-as-library", *sources, "-o", str(executable)], check=True)
        arguments = [str(executable), str(root)]
        if sys.argv[1:] == ['--clock-baseline']:
            arguments.append('--expect-vulnerable')
        if sys.argv[1:] in (['--observation-baseline'], ['--admitting-baseline']):
            arguments.append('--expect-vulnerable')
        if sys.argv[1:] in (['--admitting'], ['--admitting-baseline']):
            arguments.append('--admitting')
        if sys.argv[1:] == ['--clock-heartbeat-baseline']:
            arguments.append('--expect-heartbeat-vulnerable')
        if sys.argv[1:] in (['--restart-baseline'], ['--restart-stale-baseline']):
            arguments.append('--expect-vulnerable')
        if sys.argv[1:] in (['--restart-stale'], ['--restart-stale-baseline']):
            arguments.append('--stale-native-rules')
        # The main fixture contains many separately bounded transitions. Its
        # aggregate budget is not a control-response or protection deadline;
        # preserve those native assertions while allowing slower hosted I/O.
        subprocess.run(arguments, check=True, timeout=300)
    finally:
        for pid_file in [root / "runtime/active/pid", root / "lock-holder.pid"]:
            if not pid_file.exists():
                continue
            pid = int(pid_file.read_text())
            command = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout
            if str(root) in command and ("claude-guard-worker worker-input" in command or "CoreFixture --hold-lock" in command):
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.3)
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
