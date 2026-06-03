#!/bin/bash
set -euo pipefail

VERSION="${1:-0.2.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "Building Soteria Aegis v$VERSION for macOS..."

# Build
cd "$ROOT/desktop" && cargo build --release
cd "$ROOT/rust-core" && cargo build --release

# Create .app bundle
APP="$ROOT/packaging/macos/Soteria.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$ROOT/desktop/target/release/SoteriaAegis" "$APP/Contents/MacOS/"
cp "$ROOT/rust-core/target/release/soteriad" "$APP/Contents/MacOS/"
cp "$ROOT/config/soteria.toml" "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Soteria Aegis</string>
    <key>CFBundleDisplayName</key><string>Soteria Aegis</string>
    <key>CFBundleIdentifier</key><string>com.soteria.aegis</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>SoteriaAegis</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
EOF

# Create DMG
DMG="$ROOT/packaging/macos/SoteriaAegis-$VERSION.dmg"
rm -f "$DMG"
hdiutil create -volname "Soteria Aegis $VERSION" -srcfolder "$APP" -ov -format UDZO "$DMG"

echo "Done! DMG: $DMG"
