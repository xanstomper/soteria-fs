#!/bin/bash
set -euo pipefail

VERSION="${1:-0.2.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(dirname "$0")"

echo "Building Soteria Aegis v$VERSION for Linux..."

# Build
cd "$ROOT/rust-core" && cargo build --release
cd "$ROOT/desktop" && cargo build --release

# ── DEB ──────────────────────────────────────────────────────────────
echo "Building .deb..."
DEB="$ROOT/packaging/linux/soteria_${VERSION}_amd64"
rm -rf "$DEB"
mkdir -p "$DEB/DEBIAN" "$DEB/usr/local/bin" "$DEB/etc/soteria" "$DEB/var/lib/soteria" "$DEB/usr/lib/systemd/system" "$DEB/etc/udev/rules.d" "$DEB/usr/share/doc/soteria"

cat > "$DEB/DEBIAN/control" << EOF
Package: soteria
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Depends: libfuse3-3, adduser
Maintainer: Soteria Team <team@soteria.dev>
Description: Hardware-rooted encrypted security platform
 Soteria Aegis provides post-quantum encryption, intrusion detection,
 honey filesystems, and capability-based access control.
EOF

cat > "$DEB/DEBIAN/postinst" << 'POST'
#!/bin/bash
set -e
getent group tss >/dev/null || groupadd -r tss
getent passwd soteria >/dev/null || useradd -r -g tss -d /dev/null -s /sbin/nologin soteria
chown -R soteria:tss /etc/soteria /var/lib/soteria
systemctl daemon-reload
POST
chmod 755 "$DEB/DEBIAN/postinst"

cp "$ROOT/rust-core/target/release/soteriad" "$DEB/usr/local/bin/"
cp "$ROOT/desktop/target/release/SoteriaAegis" "$DEB/usr/local/bin/"
cp "$ROOT/config/soteria.toml" "$DEB/etc/soteria/"
cp "$SCRIPT_DIR/systemd/soteria.service" "$DEB/usr/lib/systemd/system/"
cp "$SCRIPT_DIR/udev/70-soteria-tpm.rules" "$DEB/etc/udev/rules.d/"

dpkg-deb --build "$DEB"
echo "DEB: ${DEB}.deb"

# ── RPM ──────────────────────────────────────────────────────────────
echo "Building .rpm..."
RPM_ROOT="$ROOT/packaging/linux/rpm"
rm -rf "$RPM_ROOT"
mkdir -p "$RPM_ROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > "$RPM_ROOT/SPECS/soteria.spec" << EOF
Name:           soteria
Version:        $VERSION
Release:        1
Summary:        Hardware-rooted encrypted security platform
License:        MIT
URL:            https://github.com/xanstomper/soteria-fs
Requires:       fuse3

%description
Soteria Aegis provides post-quantum encryption, intrusion detection,
and capability-based access control.

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/soteria
mkdir -p %{buildroot}/var/lib/soteria
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/udev/rules.d
install -m 755 $ROOT/rust-core/target/release/soteriad %{buildroot}/usr/local/bin/
install -m 755 $ROOT/desktop/target/release/SoteriaAegis %{buildroot}/usr/local/bin/
install -m 644 $ROOT/config/soteria.toml %{buildroot}/etc/soteria/
install -m 644 $SCRIPT_DIR/systemd/soteria.service %{buildroot}/usr/lib/systemd/system/
install -m 644 $SCRIPT_DIR/udev/70-soteria-tpm.rules %{buildroot}/etc/udev/rules.d/

%files
/usr/local/bin/soteriad
/usr/local/bin/SoteriaAegis
%config(noreplace) /etc/soteria/soteria.toml
/usr/lib/systemd/system/soteria.service
/etc/udev/rules.d/70-soteria-tpm.rules

%post
systemctl daemon-reload
EOF

rpmbuild --define "_topdir $RPM_ROOT" -ba "$RPM_ROOT/SPECS/soteria.spec"
echo "RPM: $RPM_ROOT/RPMS/"

echo "Done!"
