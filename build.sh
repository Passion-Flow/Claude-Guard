#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
version=0.4.0
swift_compiler="$(xcrun --sdk macosx --find swiftc)"
swift_sdk="$(xcrun --sdk macosx --show-sdk-path)"
swift_options=(-sdk "$swift_sdk")
if swift_platform="$(xcrun --sdk macosx --show-sdk-platform-path 2>/dev/null)"; then
  swift_plugins="$swift_platform/Developer/usr/lib/swift/host/plugins"
  if [[ -d "$swift_plugins" ]]; then swift_options+=(-plugin-path "$swift_plugins"); fi
fi
build="$(mktemp -d "${GUARD_BUILD_ROOT:-${TMPDIR:-/tmp}}/claude-guard-release.XXXXXX")"
trap 'rm -rf "$build"' EXIT
output="${GUARD_OUTPUT_DIR:-$PWD/dist}"
mkdir -p "$output" "$build/payload/Applications" "$build/packages" "$build/image" "$build/empty"
# Private builds pin ad-hoc code hashes. No paid certificate is needed.
identity="${CODESIGN_IDENTITY:--}"
team="${GUARD_TEAM_ID:-}"
if [[ "$identity" == - && -n "$team" ]] || [[ "$identity" != - && -z "$team" ]]; then
  echo 'Supply both CODESIGN_IDENTITY and GUARD_TEAM_ID, or neither for a private build.' >&2
  exit 2
fi
sign() {
  if [[ "$identity" == - ]]; then
    codesign --force --options runtime --identifier "$2" --sign - "$1"
  else
    codesign --force --options runtime --identifier "$2" --timestamp --sign "$identity" "$1"
  fi
  codesign --verify --strict --deep "$1"
}
universal() {
  local destination="$1"
  shift
  "$swift_compiler" "${swift_options[@]}" -swift-version 5 -target arm64-apple-macos13.0 -O -file-prefix-map "$PWD"=. -file-prefix-map "$build"=Build "$@" -o "$destination.arm64" &
  local arm_pid=$!
  "$swift_compiler" "${swift_options[@]}" -swift-version 5 -target x86_64-apple-macos13.0 -O -file-prefix-map "$PWD"=. -file-prefix-map "$build"=Build "$@" -o "$destination.x86_64" &
  local intel_pid=$!
  local arm_status=0 intel_status=0
  wait "$arm_pid" || arm_status=$?
  wait "$intel_pid" || intel_status=$?
  [[ "$arm_status" == 0 ]] || return "$arm_status"
  [[ "$intel_status" == 0 ]] || return "$intel_status"
  lipo -create "$destination.arm64" "$destination.x86_64" -output "$destination"
  rm "$destination.arm64" "$destination.x86_64"
}
/usr/bin/python3 -I - "$build/PrivilegedSource.swift" "$team" <<'PY'
from pathlib import Path
import base64
import re
import sys
team = sys.argv[2]
if team and re.fullmatch(r'[A-Z0-9]{10}', team) is None:
    raise SystemExit('GUARD_TEAM_ID must contain ten uppercase letters or digits')
value = base64.b64encode(Path('Sources/GuardWorker.sh').read_bytes()).decode()
Path(sys.argv[1]).write_text('import Foundation\nlet privilegedWorker = String(decoding: Data(base64Encoded: "'+value+'")!, as: UTF8.self)\nlet guardSigningTeam = "'+team+'"\n')
PY
app="$build/payload/Applications/Claude Guard.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
universal "$app/Contents/MacOS/ClaudeGuard" Sources/*.swift "$build/PrivilegedSource.swift"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>Claude Guard</string>
<key>CFBundleExecutable</key><string>ClaudeGuard</string>
<key>CFBundleIdentifier</key><string>org.claudeguard.mac</string>
<key>CFBundleIconFile</key><string>Guard</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>Claude Guard</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.4.0</string>
<key>CFBundleVersion</key><string>30</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
xcrun --sdk macosx swift "${swift_options[@]}" Art/Icon.swift "$build/Icon.png"
mkdir -p "$build/Guard.iconset"
for side in 16 32 128 256 512; do
  sips -z "$side" "$side" "$build/Icon.png" --out "$build/Guard.iconset/icon_${side}x${side}.png" >/dev/null
  double=$((side * 2))
  sips -z "$double" "$double" "$build/Icon.png" --out "$build/Guard.iconset/icon_${side}x${side}@2x.png" >/dev/null
done
iconutil -c icns "$build/Guard.iconset" -o "$app/Contents/Resources/Guard.icns"
cp -R Resources/. "$app/Contents/Resources/"
for name in OfflineRecovery Uninstall; do
  scripts=Installer/RecoveryScripts
  [[ "$name" != Uninstall ]] || scripts=Installer/UninstallScripts
  pkgbuild --root "$build/empty" --scripts "$scripts" --identifier "org.claudeguard.private.$name" \
    --version "$version" --install-location / --ownership recommended "$build/image/$name.pkg" >/dev/null
  cp "$build/image/$name.pkg" "$app/Contents/Resources/"
done
sign "$app" org.claudeguard.mac
helperdir="$build/payload/Library/PrivilegedHelperTools/org.claudeguard"
mkdir -p "$helperdir" "$build/payload/Library/LaunchDaemons"
shared=(Sources/NodeAdmission.swift Sources/GuardRiskPolicy.swift Sources/GuardService.swift Sources/GuardianTrust.swift Sources/GuardianStore.swift)
universal "$helperdir/GuardDaemon" "${shared[@]}" Daemon/*.swift "$build/PrivilegedSource.swift"
universal "$helperdir/GuardOfflineRecovery" -D GUARD_OFFLINE_RECOVERY "${shared[@]}" Daemon/*.swift "$build/PrivilegedSource.swift"
sign "$helperdir/GuardDaemon" org.claudeguard.daemon
sign "$helperdir/GuardOfflineRecovery" org.claudeguard.offline-recovery
cp Daemon/org.claudeguard.daemon.plist Daemon/org.claudeguard.offline-recovery.plist "$build/payload/Library/LaunchDaemons/"
mkdir -p "$build/payload/Library/LaunchAgents"
cp Daemon/org.claudeguard.mac.agent.plist "$build/payload/Library/LaunchAgents/org.claudeguard.mac.plist"
/usr/bin/python3 -I - "$build/payload" <<'PY'
from pathlib import Path
import json
import re
import subprocess
import sys
root = Path(sys.argv[1])
paths = {'org.claudeguard.mac': 'Applications/Claude Guard.app',
         'org.claudeguard.daemon': 'Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon',
         'org.claudeguard.offline-recovery': 'Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery'}
hashes = {}
for identifier, path in paths.items():
    values = []
    for arch in ('arm64', 'x86_64'):
        result = subprocess.run(['codesign', '-d', '--arch', arch, '--verbose=4', str(root / path)], capture_output=True, text=True, check=True)
        found = re.findall(r'^CDHash=([0-9a-f]{40})$', result.stderr, re.M)
        if len(found) != 1:
            raise SystemExit('Cannot determine exact code hash for ' + identifier)
        values.extend(found)
    hashes[identifier] = sorted(set(values))
(root / 'Library/PrivilegedHelperTools/org.claudeguard/install-trust-template.json').write_text(
    json.dumps({'schemaVersion': 2, 'ownerUID': 0, 'hashes': hashes}, sort_keys=True) + '\n')
PY
"$helperdir/GuardDaemon" --validate-payload "$build/payload"
if "$app/Contents/MacOS/ClaudeGuard" --self-test; then echo 'Production app exposes diagnostic entry points.' >&2; exit 1; else [[ "$?" == 64 ]]; fi
if "$helperdir/GuardDaemon" --self-test "$build"; then echo 'Production helper exposes diagnostic entry points.' >&2; exit 1; else [[ "$?" == 64 ]]; fi
diagnostic="$build/diagnostic/Claude Guard.app"
mkdir -p "$build/diagnostic"
cp -R "$app" "$diagnostic"
"$swift_compiler" "${swift_options[@]}" -swift-version 5 -target "$(uname -m)-apple-macos13.0" -O -D GUARD_DIAGNOSTICS \
  Sources/*.swift "$build/PrivilegedSource.swift" -o "$diagnostic/Contents/MacOS/ClaudeGuard"
sign "$diagnostic" org.claudeguard.mac
"$diagnostic/Contents/MacOS/ClaudeGuard" --self-test
if [[ "${RENDER_PREVIEWS:-0}" == 1 ]]; then "$diagnostic/Contents/MacOS/ClaudeGuard" --preview "$output/previews"; fi
"$swift_compiler" "${swift_options[@]}" -swift-version 5 -target "$(uname -m)-apple-macos13.0" -O -D GUARD_DIAGNOSTICS \
  "${shared[@]}" Daemon/*.swift "$build/PrivilegedSource.swift" -o "$build/GuardDiagnostics"
"$build/GuardDiagnostics" --self-test "$build"
"$swift_compiler" "${swift_options[@]}" -swift-version 5 -parse-as-library -O Tests/xpc_identity_fixture.swift -o "$build/IdentityFixture"
sign "$build/IdentityFixture" org.claudeguard.identity-fixture
"$build/IdentityFixture"
"$swift_compiler" "${swift_options[@]}" -swift-version 5 -parse-as-library -O Sources/NodeAdmission.swift Sources/ShadowrocketProfile.swift \
  Sources/GuardRiskPolicy.swift Tests/profile_metadata_fixture.swift -o "$build/ProfileMetadataFixture"
"$build/ProfileMetadataFixture"
plutil -lint "$app/Contents/Info.plist" Daemon/*.plist Resources/*.lproj/*.strings RecoveryResources/*.lproj/*.strings
pkgbuild --analyze --root "$build/payload" "$build/components.plist" >/dev/null
/usr/bin/python3 -I - "$build/components.plist" <<'PY'
from pathlib import Path
import plistlib
import sys
path = Path(sys.argv[1])
components = plistlib.loads(path.read_bytes())
for component in components:
    component['BundleIsRelocatable'] = False
    component['BundleHasStrictIdentifier'] = True
    component['BundleOverwriteAction'] = 'upgrade'
path.write_bytes(plistlib.dumps(components))
PY
pkgbuild --root "$build/payload" --scripts Installer/Scripts --identifier org.claudeguard.private \
  --component-plist "$build/components.plist" --version "$version" --install-location / --ownership recommended "$build/packages/ClaudeGuardComponent.pkg" >/dev/null
package="$output/Claude-Guard-Mac-$version-private.pkg"
product_args=(--distribution Installer/Distribution.xml --resources Installer/Resources --package-path "$build/packages")
if [[ -n "${INSTALLER_IDENTITY:-}" ]]; then product_args+=(--sign "$INSTALLER_IDENTITY" --timestamp); fi
productbuild "${product_args[@]}" "$package" >/dev/null
# Expansion inspects the archive without executing scripts or registering a job.
pkgutil --expand-full "$package" "$build/expanded"
/usr/bin/python3 -I - "$build/expanded" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1]) / 'ClaudeGuardComponent.pkg'
for name in ('preinstall', 'postinstall'):
    if (root / 'Scripts' / name).read_bytes() != (Path('Installer/Scripts') / name).read_bytes():
        raise SystemExit('Installer hook was not preserved')
for name in ('Claude Guard.app',):
    if not (root / 'Payload/Applications' / name / 'Contents/MacOS/ClaudeGuard').is_file():
        raise SystemExit('Application missing from expanded package')
PY
"$helperdir/GuardDaemon" --validate-payload "$build/expanded/ClaudeGuardComponent.pkg/Payload"
cp "$package" "$build/image/"
cp Docs/Installation.md "$build/image/Installation.md"
cp Docs/Acceptance.md "$build/image/Acceptance.md"
image="$output/Claude-Guard-Mac-$version-private.dmg"
hdiutil create -ov -format UDZO -volname 'Claude Guard' -srcfolder "$build/image" "$image" >/dev/null
hdiutil verify "$image"
if [[ "$identity" != - && -n "${NOTARY_PROFILE:-}" ]]; then
  [[ -n "${INSTALLER_IDENTITY:-}" ]] || { echo 'Notarization requires a signed installer.' >&2; exit 2; }
  xcrun notarytool submit "$image" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$image"
fi
(cd "$output" && shasum -a 256 "$(basename "$package")" "$(basename "$image")" > SHA256SUMS)
echo 'PASS: universal private installer, pinned payload, offline diagnostics and archive inspection; no live installation performed.'
