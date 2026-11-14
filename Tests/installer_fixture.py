"""Exercise installer hooks against disposable paths and mock launchd/helpers."""
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET

REPOSITORY = Path(__file__).resolve().parents[1]
for name in ('org.claudeguard.daemon', 'org.claudeguard.offline-recovery'):
    job = plistlib.loads((REPOSITORY / 'Daemon' / (name + '.plist')).read_bytes())
    assert job['ProcessType'] == 'Interactive', 'Deadline-bound network protection must not be discretionary background work'
distribution = ET.fromstring((REPOSITORY / 'Installer/Distribution.xml').read_text())
assert distribution.find("pkg-ref[@id='org.claudeguard.private']/must-close/app[@id='org.claudeguard.mac']") is not None
with tempfile.TemporaryDirectory(prefix="cg-installer-test-") as work:
    root = Path(work)
    library = root / "Library"
    directory = library / "PrivilegedHelperTools/org.claudeguard"
    directory.mkdir(parents=True)
    jobs = library / "LaunchDaemons"
    jobs.mkdir()
    agents = library / "LaunchAgents"
    agents.mkdir()
    (agents / "org.claudeguard.mac.plist").write_text("fixture")
    for label in ("org.claudeguard.daemon", "org.claudeguard.offline-recovery"):
        (jobs / (label + ".plist")).write_text("fixture")
    (directory / "install-trust-template.json").write_text("fixture")
    helper = '''#!/usr/bin/python3
from pathlib import Path
import sys
root=Path(__file__).parents[3]
name=Path(__file__).name
action=sys.argv[1]
with (root/'events').open('a') as stream: print(name,action,file=stream)
if (root/('fail-'+name)).exists(): sys.exit(74)
if action=='--prepare-upgrade': (root/'rules').write_text('SEALED')
if action in ('--restore-local','--uninstall'): (root/'rules').write_text('CLEAR')
if action=='--initialize': (Path(__file__).parent/'install-trust.json').write_text('fixture')
'''
    for name in ("GuardDaemon", "GuardOfflineRecovery"):
        (directory / name).write_text(helper)
        (directory / name).chmod(0o755)
    standalone = root / "GuardUninstall"
    standalone.write_text('#!/bin/sh\n[ "$1" = --uninstall ] || exit 64\nexit 0\n')
    standalone.chmod(0o755)
    launchctl = root / "launchctl"
    launchctl.write_text('''#!/usr/bin/python3
from pathlib import Path
import sys
root=Path(__file__).parent
action=sys.argv[1]
label=Path(sys.argv[-1]).stem if action=='bootstrap' else sys.argv[-1].removeprefix('system/')
state=root/('job-'+label)
with (root/'events').open('a') as stream: print('launchctl',action,label,file=stream)
if action=='bootstrap':
    if (root/'fail-bootstrap').exists(): sys.exit(1)
    state.touch()
elif action=='bootout':
    if not (root/'fail-bootout').exists(): state.unlink(missing_ok=True)
elif action=='print': sys.exit(0 if state.exists() else 1)
else: sys.exit(64)
'''.replace(".removeprefix('system/')", ".replace('system/', '', 1)"))
    launchctl.chmod(0o755)

    def run(name, target="/"):
        text = (REPOSITORY / "Installer" / name).read_text()
        text = text.replace('$(/usr/bin/id -u)', '0').replace('/usr/sbin/chown', '/usr/bin/true')
        text = text.replace("$(/usr/bin/stat -f '%u' /dev/console)", '0')
        text = text.replace('/bin/launchctl', str(launchctl)).replace('/Library/', str(library) + '/')
        text = text.replace('$(/usr/bin/dirname "$0")/GuardUninstall', str(standalone))
        return subprocess.run(['/bin/sh', '-c', text, 'fixture', 'fixture.pkg', '/', target],
                              capture_output=True, text=True)

    assert run("Scripts/preinstall").returncode == 0
    assert run("Scripts/postinstall").returncode == 0
    assert (directory / "install-trust.json").exists()
    assert (root / "job-org.claudeguard.daemon").exists()
    assert run("Scripts/preinstall", "/other-volume").returncode != 0
    (root / "fail-GuardDaemon").touch()
    assert run("Scripts/preinstall").returncode != 0
    assert (root / "job-org.claudeguard.daemon").exists()
    (root / "fail-GuardDaemon").unlink()
    (root / "fail-bootout").touch()
    assert run("Scripts/preinstall").returncode != 0
    assert (root / "rules").read_text() == "SEALED"
    (root / "fail-bootout").unlink()
    assert run("Scripts/preinstall").returncode == 0
    assert not (root / "job-org.claudeguard.daemon").exists()
    (root / "fail-bootstrap").touch()
    assert run("Scripts/postinstall").returncode != 0
    assert (root / "rules").read_text() == "SEALED"
    (root / "fail-bootstrap").unlink()
    assert run("Scripts/postinstall").returncode == 0
    legacy = jobs / "org.claudeguard.guardian.plist"
    legacy.touch()
    assert run("Scripts/preinstall").returncode != 0
    legacy.unlink()
    assert run("RecoveryScripts/postinstall").returncode == 0
    assert (root / "rules").read_text() == "CLEAR"
    (root / "fail-GuardDaemon").touch()
    (directory / "GuardOfflineRecovery").unlink()
    (directory / "GuardDaemon").unlink()
    assert run("UninstallScripts/postinstall").returncode == 0
    assert run("UninstallScripts/postinstall", "/other-volume").returncode != 0
    tree = ET.parse(REPOSITORY / "Installer/Distribution.xml")
    assert tree.find("domains").attrib["enable_currentUserHome"] == "false"
    assert tree.find("options").attrib["rootVolumeOnly"] == "true"
    print("PASS: clean installation, sealed upgrade, failed preparation/bootout/bootstrap, legacy refusal, offline recovery and independent package uninstall")
