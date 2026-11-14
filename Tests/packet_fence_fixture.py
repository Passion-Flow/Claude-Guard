"""Run actual native fence code with a disposable unprivileged PF substitute."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-packet-fence-') as temporary:
    root = Path(temporary)
    (root / 'state').mkdir(mode=0o700)
    command = root / 'pfctl'
    command.write_text('''#!/usr/bin/python3
from pathlib import Path
import sys,time
root=Path(__file__).parent
args=sys.argv[1:]
if (root/'slow-commands').exists():
 (root/'slow-entered').touch()
 time.sleep(3.3)
rules=root/'rules'
if '-f' in args:
 body=sys.stdin.read().strip()
 if '-n' in args:
  if 'CG_BLOCK' in body and 'CG_TUNNEL' not in body:(root/'seal-entered').touch()
  print(body)
 else:
  if 'CG_TUNNEL' in body and (root/'hold').exists():
   (root/'entered').touch()
   while (root/'hold').exists():time.sleep(.01)
  rules.write_text(body)
  if 'CG_TUNNEL' in body:(root/'writer-finished').touch()
elif '-sr' in args:print(rules.read_text() if rules.exists() else '')
elif args==['-F','states']:pass
elif args==['-s','info']:
 status=root/'pf-status'
 print('Status: '+(status.read_text() if status.exists() else 'Enabled'))
elif args==['-E']:
 (root/'pf-status').write_text('Enabled')
 print('Token : 773',file=sys.stderr)
elif args==['-X','773']:(root/'native-token-released').touch()
else:raise SystemExit(64)
''')
    command.chmod(0o700)
    executable = root / 'FenceFixture'
    constants = root / 'power-messages.c'
    constants.write_text('''#include <stdio.h>
#include <IOKit/IOMessage.h>
int main(void) {
 printf("%u %u %u %u %u", kIOMessageCanSystemSleep, kIOMessageSystemWillSleep,
 kIOMessageSystemWillPowerOn, kIOMessageSystemHasPoweredOn, kIOMessageSystemWillNotSleep);
 return 0;
}
''')
    probe = root / 'PowerMessageProbe'
    subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', str(constants), '-o', str(probe)], check=True)
    message_values = subprocess.check_output([str(probe)], text=True).split()
    sources = ['Sources/NodeAdmission.swift', 'Sources/GuardRiskPolicy.swift',
               'Sources/GuardService.swift', 'Sources/GuardianStore.swift', 'Sources/GuardianTrust.swift',
               'Daemon/GuardianRecovery.swift', 'Daemon/GuardianPacketFence.swift',
               'Daemon/GuardianPowerObserver.swift', 'Tests/packet_fence_fixture.swift']
    subprocess.run(['swiftc', '-swift-version', '5', '-O', '-D', 'GUARD_DIAGNOSTICS', '-parse-as-library',
                    *[str(ROOT / name) for name in sources], '-o', str(executable)], check=True)
    subprocess.run([str(executable), str(root), *message_values], check=True, timeout=60)
