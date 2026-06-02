#!/bin/bash
# Soteria Linux Packaging (deb + rpm)
#
# Usage:
#   bash packaging/linux/build-packages.sh [version]

set -euo pipefail

VERSION="${1:-0.1.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT/rust-core/target/release"
SCRIPT_DIR="$(dirname "$0")"

echo "Building Soteria v$VERSION for Linux..."

# Build
cd "$ROOT/rust-core"
cargo build --release

# ── DEB ──────────────────────────────────────────────────────────────

echo "Building .deb..."

DEB_DIR="$ROOT/packaging/linux/soteria_${VERSION}_amd64"
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/local/bin"
mkdir -p "$DEB_DIR/etc/soteria"
mkdir -p "$DEB_DIR/var/lib/soteria"
mkdir -p "$DEB_DIR/usr/share/doc/soteria"
mkdir -p "$DEB_DIR/usr/lib/systemd/system"
mkdir -p "$DEB_DIR/etc/udev/rules.d"

cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: soteria
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Depends: libfuse3-3, adduser
Maintainer: Soteria Team <team@soteria.dev>
Description: Hardware-rooted encrypted security platform
 Soteria is a modern encrypted security platform with post-quantum
 file sharing, per-block encryption, capability-based access control,
 honey filesystem, and canary intrusion detection.
EOF

cat > "$DEB_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e
if ! getent group tss > /dev/null 2>&1; then
    addgroup --system tss
fi
if ! id -u soteria > /dev/null 2>&1; then
    adduser --system --ingroup tss --no-create-home soteria
fi
chown -R soteria:tss /etc/soteria /var/lib/soteria
systemctl daemon-reload
udevadm control --reload-rules
echo "Soteria installed. Start with: systemctl start soteria"
POSTINST
chmod 755 "$DEB_DIR/DEBIAN/postinst"

cp "$BUILD_DIR/soteriad" "$DEB_DIR/usr/local/bin/"
cp "$ROOT/rust-core/config/soteria.toml" "$DEB_DIR/etc/soteria/"
cp "$SCRIPT_DIR/systemd/soteria.service" "$DEB_DIR/usr/lib/systemd/system/"
cp "$SCRIPT_DIR/udev/70-soteria-tpm.rules" "$DEB_DIR/etc/udev/rules.d/"

cat > "$DEB_DIR/usr/share/doc/soteria/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: soteria
Upstream-Contact: team@soteria.dev
Source: https://github.com/example/soteria-fs

Files: *
Copyright: 2026 Soteria Team
License: MIT
EOF

dpkg-deb --build "$DEB_DIR"
echo "DEB: ${DEB_DIR}.deb"

# ── RPM ──────────────────────────────────────────────────────────────

echo "Building .rpm..."

RPM_ROOT="$ROOT/packaging/linux/rpm"
rm -rf "$RPM_ROOT"
mkdir -p "$RPM_ROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > "$RPM_ROOT/SPECS/soteria.spec" << EOF
Name:           soteria
Version:        $VERSION
Release:        1%{?dist}
Summary:        Hardware-rooted encrypted security platform
License:        MIT
URL:            https://github.com/example/soteria-fs
Requires:       fuse3

%description
Soteria is a modern encrypted security platform with post-quantum
file sharing, per-block encryption, and intelligent threat containment.

%pre
getent group tss >/dev/null || groupadd -r tss
getent passwd soteria >/dev/null || useradd -r -g tss -d /dev/null -s /sbin/nologin soteria

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/soteria
mkdir -p %{buildroot}/var/lib/soteria
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/udev/rules.d
install -m 755 $BUILD_DIR/soteriad %{buildroot}/usr/local/bin/
install -m 644 $ROOT/rust-core/config/soteria.toml %{buildroot}/etc/soteria/
install -m 644 $SCRIPT_DIR/systemd/soteria.service %{buildroot}/usr/lib/systemd/system/
install -m 644 $SCRIPT_DIR/udev/70-soteria-tpm.rules %{buildroot}/etc/udev/rules.d/

%files
/usr/local/bin/soteriad
%config(noreplace) /etc/soteria/soteria.toml
/usr/lib/systemd/system/soteria.service
/etc/udev/rules.d/70-soteria-tpm.rules
%dir /var/lib/soteria

%post
systemctl daemon-reload
udevadm control --reload-rules
chown -R soteria:tss /etc/soteria /var/lib/soteria

%changelog
* $(date '+%a %b %d %Y') Soteria Team <team@soteria.dev> - $VERSION-1
- Initial release
EOF

rpmbuild --define "_topdir $RPM_ROOT" -ba "$RPM_ROOT/SPECS/soteria.spec"
echo "RPM: $RPM_ROOT/RPMS/"

echo ""
echo "Packages built successfully!"
