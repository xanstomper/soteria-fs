#!/bin/bash
# Soteria Release Script
#
# Usage:
#   bash scripts/release.sh 0.2.0

set -euo pipefail

VERSION="${1:?Usage: scripts/release.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Preparing Soteria v$VERSION release..."

# Update version in Cargo.toml
cd "$ROOT/rust-core"
sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml

# Update CHANGELOG
cd "$ROOT"
DATE=$(date +%Y-%m-%d)
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [$VERSION] - $DATE/" CHANGELOG.md

# Run tests
echo "Running tests..."
cd "$ROOT/rust-core"
cargo test --all-targets

# Run clippy
echo "Running clippy..."
cargo clippy --all-targets -- -D warnings

# Check formatting
echo "Checking formatting..."
cargo fmt --check

# Build release
echo "Building release..."
cargo build --release

# Create git tag
cd "$ROOT"
git add -A
git commit -m "release: v$VERSION"
git tag -a "v$VERSION" -m "Release v$VERSION"

echo ""
echo "Release v$VERSION prepared!"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git log --oneline -5"
echo "  2. Push: git push origin main --tags"
echo "  3. GitHub Actions will build and publish the release"
