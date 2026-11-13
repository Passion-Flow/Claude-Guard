"""Exercise real discovery with bounded deterministic OS observations only."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-discovery-test-') as directory:
    binary = Path(directory) / 'DiscoveryFixture'
    inputs = ['Sources/NodeAdmission.swift', 'Sources/GuardRiskPolicy.swift',
              'Sources/GuardService.swift', 'Sources/GuardianTrust.swift',
              'Sources/ShadowrocketProfile.swift', 'Sources/AutomaticDiscovery.swift',
              'Tests/automatic_discovery_fixture.swift']
    subprocess.run(['swiftc', '-swift-version', '5', '-O', '-parse-as-library',
                    *[str(ROOT / name) for name in inputs], '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
