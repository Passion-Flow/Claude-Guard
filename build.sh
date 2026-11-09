#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
build="$(mktemp -d /tmp/claude-guard-release.XXXXXX)"
output="$PWD/dist"
mkdir -p "$output"
python3 - "$build/PrivilegedSource.swift" <<'PY'
from pathlib import Path
import base64
import sys
value = base64.b64encode(Path('Sources/GuardWorker.sh').read_bytes()).decode()
Path(sys.argv[1]).write_text('import Foundation\nlet privilegedWorker = String(decoding: Data(base64Encoded: "'+value+'")!, as: UTF8.self)\n')
PY
app="$build/stage/Claude Guard.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
swiftc -swift-version 5 -target arm64-apple-macos13.0 -O -o "$build/ClaudeGuard-arm64" Sources/*.swift "$build/PrivilegedSource.swift" &
arm_pid=$!
swiftc -swift-version 5 -target x86_64-apple-macos13.0 -O -o "$build/ClaudeGuard-x86_64" Sources/*.swift "$build/PrivilegedSource.swift" &
intel_pid=$!
wait "$arm_pid"
wait "$intel_pid"
lipo -create "$build/ClaudeGuard-arm64" "$build/ClaudeGuard-x86_64" -output "$app/Contents/MacOS/ClaudeGuard"
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
<key>CFBundleShortVersionString</key><string>0.2.6</string>
<key>CFBundleVersion</key><string>8</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
swift Art/Icon.swift "$build/Icon.png"
mkdir -p "$build/Guard.iconset"
for side in 16 32 128 256 512; do
  sips -z "$side" "$side" "$build/Icon.png" --out "$build/Guard.iconset/icon_$side"x"$side.png" >/dev/null
  double=$((side * 2))
  sips -z "$double" "$double" "$build/Icon.png" --out "$build/Guard.iconset/icon_$side"x"$side@2x.png" >/dev/null
done
iconutil -c icns "$build/Guard.iconset" -o "$app/Contents/Resources/Guard.icns"
cp -R Resources/. "$app/Contents/Resources/"
plutil -lint "$app/Contents/Info.plist" Resources/*.lproj/*.strings RecoveryResources/*.lproj/*.strings
sign_app() {
  if [[ "$signing_identity" == "-" ]]; then
    codesign --force --options runtime --timestamp=none --sign - "$1"
  else
    codesign --force --options runtime --timestamp --sign "$signing_identity" "$1"
  fi
  codesign --verify --strict --deep "$1"
}
signing_identity="${GUARD_CODESIGN_IDENTITY:--}"
sign_app "$app"
diagnostics="$build/diagnostics/Claude Guard.app"
mkdir -p "$diagnostics"
cp -R "$app/Contents" "$diagnostics/"
swiftc -swift-version 5 -target "$(uname -m)-apple-macos13.0" -D GUARD_DIAGNOSTICS -O \
  -o "$diagnostics/Contents/MacOS/ClaudeGuard" Sources/*.swift "$build/PrivilegedSource.swift"
codesign --force --sign - "$diagnostics"
"$diagnostics/Contents/MacOS/ClaudeGuard" --self-test
if [[ "${RENDER_PREVIEWS:-0}" == 1 ]]; then
  "$diagnostics/Contents/MacOS/ClaudeGuard" --preview "$output/previews"
fi
if "$app/Contents/MacOS/ClaudeGuard" --self-test; then
  echo "Release binary accepted a diagnostic entry point." >&2
  exit 1
else
  [[ "$?" -eq 64 ]]
fi
lipo -info "$app/Contents/MacOS/ClaudeGuard"
recovery="$build/stage/Claude Guard Recovery.app"
cp -R "$app" "$recovery"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier org.claudeguard.recovery" "$recovery/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName Claude Guard Recovery" "$recovery/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Claude Guard Recovery" "$recovery/Contents/Info.plist"
cp -R RecoveryResources/. "$recovery/Contents/Resources/"
sign_app "$recovery"
ln -s /Applications "$build/stage/Applications"
cp README.md "$build/stage/Installation.md"
cp Docs/Installation.zh-Hans.md "$build/stage/Installation.zh-Hans.md"
image="$output/Claude-Guard-Mac-0.2.6-beta.dmg"
hdiutil create -ov -format UDZO -volname "Claude Guard" -srcfolder "$build/stage" "$image"
hdiutil verify "$image"
