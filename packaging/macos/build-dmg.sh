#!/bin/bash
# Soteria macOS Packaging (DMG)
#
# Prerequisites:
# - Xcode command line tools
# - create-dmg (brew install create-dmg)
#
# Usage:
#   bash packaging/macos/build-dmg.sh

set -euo pipefail

VERSION="${1:-0.1.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT/rust-core/target/release"
APP_DIR="$ROOT/packaging/macos/Soteria.app"
DMG_PATH="$ROOT/packaging/macos/Soteria-$VERSION.dmg"

echo "Building Soteria v$VERSION for macOS..."

# Step 1: Build the Rust binary
echo "Building soteriad..."
cd "$ROOT/rust-core"
cargo build --release

# Step 2: Create .app bundle structure
echo "Creating .app bundle..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Step 3: Copy binary
cp "$BUILD_DIR/soteriad" "$APP_DIR/Contents/MacOS/"
cp "$ROOT/rust-core/config/soteria.toml" "$APP_DIR/Contents/Resources/"

# Step 4: Create Info.plist
cat > "$APP_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Soteria</string>
    <key>CFBundleDisplayName</key>
    <string>Soteria</string>
    <key>CFBundleIdentifier</key>
    <string>com.soteria.fs</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleExecutable</key>
    <string>soteriad</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Step 5: Create DMG
echo "Creating DMG..."
rm -f "$DMG_PATH"
create-dmg \
    --volname "Soteria $VERSION" \
    --volicon "$ROOT/packaging/macos/Soteria.icns" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "Soteria.app" 175 190 \
    --hide-extension "Soteria.app" \
    --app-drop-link 425 190 \
    "$DMG_PATH" \
    "$APP_DIR" || {
    # Fallback: simple DMG without fancy layout
    hdiutil create -volname "Soteria $VERSION" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH"
}

echo "Done! DMG: $DMG_PATH"
