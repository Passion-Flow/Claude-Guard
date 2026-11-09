"""Exercise the privileged worker with an entirely simulated PF and VPN."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1] / "Sources" / "GuardWorker.sh"

with tempfile.TemporaryDirectory(prefix="cg-worker-test-") as work:
    root = Path(work)
    runtime = root / "runtime"
    mock = root / "pfctl"
    mock.write_text("""#!/usr/bin/python3
from pathlib import Path
import sys
root = Path(__file__).parent
args = sys.argv[1:]
rules = root / 'rules'
if args == ['-sr']:
    print((root / 'main').read_text(), end='')
elif args == ['-s', 'info']:
    print('Status: Enabled')
elif args == ['-E']:
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
elif args[-1:] == ['-sr'] and args[1].startswith('com.apple/00000'):
    print(rules.read_text() if rules.exists() else '', end='')
elif args in (['-a', 'com.apple', '-s', 'Anchors'], ['-v', '-s', 'Interfaces']):
    pass
else:
    sys.exit(3)
""")
    mock.chmod(0o755)
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
    print('* VPN ' + service + ' [VPN:com.liguangming.Shadowrocket]')
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
import sys
root = Path(__file__).parent
address = sys.argv[-1].split('/')[2]
name = 'primary' if address == '1.1.1.1' else 'backup'
with (root / 'probe-log').open('a') as log:
    print(name, file=log)
drop = root / 'drop-next'
if drop.exists() and int(drop.read_text()) > 0:
    drop.write_text(str(int(drop.read_text()) - 1))
    sys.exit(28)
override = root / name
value = (override if override.exists() else root / 'exit').read_text().strip()
if value == '-':
    sys.exit(28)
print('ip=' + value)
""")
    curl.chmod(0o755)
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
""")
    ifconfig.chmod(0o755)
    standard = 'anchor "com.apple/*" all\n'
    (root / "main").write_text(standard)
    (root / "exit").write_text("192.0.2.42\n")
    script = SOURCE.read_text().replace(
        "pf=/sbin/pfctl", "pf=" + str(mock)
    ).replace(
        "directory=/var/run/org.claudeguard.runtime", "directory=" + str(runtime)
    ).replace(
        '$(/usr/bin/id -u)', "0"
    ).replace(
        "= 0:755", "= " + str(os.getuid()) + ":755"
    ).replace("/sbin/ifconfig", str(ifconfig)).replace("/usr/sbin/scutil", str(scutil)).replace("/bin/sleep 5", "/bin/sleep 1").replace("/bin/date", str(clock)).replace("/usr/bin/curl", str(curl)).replace("/usr/sbin/netstat", str(netstat))
    session = str(uuid.uuid4())

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
        raise AssertionError((phase, status()))

    # Run one full production observation window before using scaled times
    # for the remaining state-machine fixtures.
    production = ["/bin/sh", "-c", script, "claude-guard-worker"]
    worker = subprocess.Popen(
        production + ["worker", session, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("LOCKED", reason="settling")
        assert status()[12] == "ipv4-tunnel-v1"
        first = int(status()[2])
        time.sleep(4)
        assert status()[1] == "LOCKED"
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        expect("OPEN", timeout=40)
        assert int(status()[2]) - first >= 15
        assert (root / "probe-log").read_text().count("primary") >= 6
        subprocess.run(production + ["stop"], check=True, capture_output=True)
        expect("IDLE")
    finally:
        if worker.poll() is None:
            worker.terminate()
        worker.communicate(timeout=8)

    scaled = script.replace("stability_seconds=15", "stability_seconds=4").replace(
        "stability_samples=6", "stability_samples=4"
    ).replace("stability_tick=3", "stability_tick=1")
    prefix = ["/bin/sh", "-c", scaled, "claude-guard-worker"]
    session = str(uuid.uuid4())
    worker = subprocess.Popen(
        prefix + ["worker", session, "live", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        assert (root / "flushed").exists()
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

        # Sustained failure closes the tunnel after the one bounded retry round.
        (root / "primary").write_text("-")
        (root / "backup").write_text("-")
        expect("OPEN", reason="probe-retry")
        expect("LOCKED", reason="probe-failed")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "primary").unlink()
        (root / "backup").unlink()
        expect("OPEN")

        # A wrong IP is not a timeout. A working backup must not overrule it.
        (root / "primary").write_text("192.0.2.99")
        expect("LOCKED", reason="exit-mismatch")
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        (root / "primary").unlink()
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
        (root / "main").write_text(standard)
        time.sleep(3)
        assert status()[1] == "DRIFT"
        assert "CG_TUNNEL" not in (root / "rules").read_text()
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
    trial = str(uuid.uuid4())
    worker = subprocess.Popen(
        prefix + ["worker", trial, "trial", "utun6", "192.0.2.42", "tcp", "443", "192.0.2.42"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        expect("OPEN")
        (root / "clock-offset").write_text("90")
        expect("LOCKED", reason="trial-paused")
        assert status()[0] == trial and status()[8] == "paused" and status()[9] == "1"
        assert (runtime / "active").exists()
        assert "CG_BLOCK" in (root / "rules").read_text()
        assert "CG_TUNNEL" not in (root / "rules").read_text()
        subprocess.run(prefix + ["continue"], check=True, capture_output=True)
        expect("OPEN")
        assert status()[8] == "live"

        # An ordinary signal without an explicit offline restore must not clear PF.
        (root / "released").unlink()
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
    worker = subprocess.Popen(
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

print("PASS: full dwell, route change, dwell failure, clock gap, backup, one-round grace, persistent failure, wrong exit, Wi-Fi loss, stale tunnel recycle, Ethernet failover, recovery, retry, same-service utun rebinding, foreign-service denial, expiry lock, explicit continuation, unexpected exit, independent restore and saved-service rearm")
