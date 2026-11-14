"""Run pure native observation-lease controls without host state changes."""
from pathlib import Path
import subprocess
import tempfile

repository = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-observation-lease-') as directory:
    executable = Path(directory) / 'LeaseFixture'
    subprocess.run(['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-swift-version', '5', '-O',
        '-parse-as-library', str(repository / 'Daemon/GuardianObservationLease.swift'),
        str(repository / 'Tests/guardian_lease_fixture.swift'), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
