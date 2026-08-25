#!/usr/bin/env bash
# Builds a .deb package for sni-collector.
#
# Usage: packaging/build-deb.sh [version]
#   version defaults to 1.0.0. Output goes to dist/sni-collector_<version>_<arch>.deb.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-1.0.0}"
ARCH="$(dpkg --print-architecture)"
PKG="sni-collector"
DIST_DIR="$ROOT/dist"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "==> Building $PKG binary ($VERSION, $ARCH)"
CGO_ENABLED=1 go -C "$ROOT" build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
  -o "$BUILD_DIR/sni-collector" ./cmd/sni-collector

echo "==> Staging package tree"
PKGROOT="$BUILD_DIR/pkgroot"
install -d "$PKGROOT/DEBIAN"
install -d "$PKGROOT/usr/bin"
install -d "$PKGROOT/lib/systemd/system"
install -d "$PKGROOT/etc/sni-collector"
install -d "$PKGROOT/usr/share/doc/sni-collector"

install -m 0755 "$BUILD_DIR/sni-collector" "$PKGROOT/usr/bin/sni-collector"
install -m 0644 "$ROOT/packaging/sni-collector.service" "$PKGROOT/lib/systemd/system/sni-collector.service"
install -m 0640 "$ROOT/deploy/sni-collector.env" "$PKGROOT/etc/sni-collector/sni-collector.env"
install -m 0644 "$ROOT/README.md" "$PKGROOT/usr/share/doc/sni-collector/README.md"
install -m 0644 "$ROOT/packaging/copyright" "$PKGROOT/usr/share/doc/sni-collector/copyright"

sed -e "s/VERSION_PLACEHOLDER/$VERSION/" -e "s/ARCH_PLACEHOLDER/$ARCH/" \
  "$ROOT/packaging/control" > "$PKGROOT/DEBIAN/control"
install -m 0644 "$ROOT/packaging/conffiles" "$PKGROOT/DEBIAN/conffiles"
install -m 0755 "$ROOT/packaging/postinst" "$PKGROOT/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/prerm" "$PKGROOT/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/postrm" "$PKGROOT/DEBIAN/postrm"

echo "==> Computing installed size"
SIZE_KB=$(du -sk "$PKGROOT" | cut -f1)
sed -i "/^Description:/i Installed-Size: $SIZE_KB" "$PKGROOT/DEBIAN/control"

echo "==> Generating md5sums"
(cd "$PKGROOT" && find . -type f -not -path './DEBIAN/*' -printf '%P\0' \
  | xargs -0 md5sum > DEBIAN/md5sums)

mkdir -p "$DIST_DIR"
OUT="$DIST_DIR/${PKG}_${VERSION}_${ARCH}.deb"
echo "==> Building $OUT"
dpkg-deb --build --root-owner-group "$PKGROOT" "$OUT"

echo "==> Verifying"
dpkg-deb --info "$OUT"
echo
dpkg-deb --contents "$OUT"

echo
echo "Built: $OUT"
