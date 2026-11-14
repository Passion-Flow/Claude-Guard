"""Compile and exercise the real native uninstaller against disposable files."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="cg-uninstall-build-") as temporary:
    binary = Path(temporary) / "UninstallFixture"
    subprocess.run(["xcrun", "swiftc", "-swift-version", "5", "-D", "GUARD_DIAGNOSTICS",
                    "-parse-as-library", str(ROOT / "Daemon/GuardianUninstall.swift"),
                    str(ROOT / "Tests/uninstall_fixture.swift"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=45)
