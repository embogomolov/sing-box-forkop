#!/usr/bin/env bash
# Packages a sing-box-forkop binary for one OpenWrt architecture as .ipk and .apk.
# build.sh runs it once per architecture; the packages are byte-for-byte the
# same for the same binary, version and SOURCE_DATE_EPOCH.
set -euo pipefail
umask 022

PROJECT=$(cd "$(dirname "$0")/../.." && pwd)
PACKAGE=sing-box-forkop
URL=https://github.com/ushan0v/sing-box-forkop
MAINTAINER=ushan0v
LICENSE=GPL-3.0-or-later
DEPENDS=(ca-bundle)
# Every package that installs /usr/bin/sing-box. opkg removes one in the same transaction only
# when it is named here, as Conflicts and Replaces; it never follows a Provides to it.
CONFLICTS=(sing-box sing-box-tiny sing-box-extended podkop-engine podkop-engine-full sing-box-lx sing-box-x rust-x steer-box-connector)
CONFFILES=(/etc/config/sing-box /etc/sing-box/config.json)

usage() {
  echo "Usage: $0 --binary FILE --arch ARCH --version VERSION --variant NAME [--format ipk|apk|all] [--output DIR]" >&2
  exit 2
}

BINARY="" ARCHITECTURE="" VERSION="" VARIANT="" FORMAT=all OUTPUT="$PROJECT/dist"
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --binary) BINARY="$2" ;;
    --arch) ARCHITECTURE="$2" ;;
    --version) VERSION="$2" ;;
    --variant) VARIANT="$2" ;;
    --format) FORMAT="$2" ;;
    --output) OUTPUT="$2" ;;
    *) usage ;;
  esac
  shift 2
done
if [ ! -f "$BINARY" ] || [ -z "$ARCHITECTURE" ] || [ -z "$VERSION" ] || [ -z "$VARIANT" ]; then
  usage
fi
[[ "$FORMAT" =~ ^(all|ipk|apk)$ ]] || usage
# A package carries the release a build is or follows, X.Y.Z-rN for X.Y.Z-rN+K
# too: neither opkg nor apk can order a build between two releases.
PACKAGE_VERSION=${VERSION%%+*}
if ! [[ "$PACKAGE_VERSION" =~ ^[0-9]+(\.[0-9]+)*(-r[0-9]+)?$ ]]; then
  echo "$0: version $VERSION is not X.Y.Z-rN or X.Y.Z-rN+K" >&2
  exit 2
fi
: "${SOURCE_DATE_EPOCH:=$(git -C "$PROJECT" log -1 --format=%ct)}"

case "$VARIANT" in
  base|full|tiny) DESCRIPTION="sing-box for Forkop, $VARIANT build." ;;
  *) DESCRIPTION="sing-box for Forkop, custom build." ;;
esac
ASSET="$OUTPUT/${PACKAGE}_${VERSION}_${VARIANT}_${ARCHITECTURE}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"

install -Dm755 "$BINARY" "$ROOT/usr/bin/sing-box"
install -Dm644 /dev/null "$ROOT/usr/share/sing-box-forkop/version"
printf '%s\n' "$VERSION" > "$ROOT/usr/share/sing-box-forkop/version"
install -Dm644 /dev/null "$ROOT/usr/share/sing-box-forkop/variant"
printf '%s\n' "$VARIANT" > "$ROOT/usr/share/sing-box-forkop/variant"
install -Dm644 "$PROJECT/release/config/config.json" "$ROOT/etc/sing-box/config.json"
install -Dm644 "$PROJECT/release/config/openwrt.conf" "$ROOT/etc/config/sing-box"
install -Dm755 "$PROJECT/release/config/openwrt.init" "$ROOT/etc/init.d/sing-box"
install -Dm644 "$PROJECT/release/config/openwrt.keep" "$ROOT/lib/upgrade/keep.d/sing-box"
install -Dm644 "$PROJECT/LICENSE" "$ROOT/usr/share/licenses/sing-box/LICENSE"

comma_list() {
  local joined
  printf -v joined '%s, ' "$@"
  echo "${joined%, }"
}

# tar and apk both record modification times; pinning them is what makes two
# builds of the same commit produce the same package.
pin_mtimes() {
  find "$1" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

tar_gz() {
  tar -C "$1" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --format=gnu -cf - "${@:2}" | gzip -9n
}

build_ipk() {
  local control="$WORK/ipk/control" outer="$WORK/ipk/outer" installed_size
  mkdir -p "$control" "$outer"
  installed_size=$(du -sb "$ROOT" | cut -f1)
  cat > "$control/control" <<EOF
Package: $PACKAGE
Version: $PACKAGE_VERSION
Depends: $(comma_list "${DEPENDS[@]}")
Provides: sing-box
Conflicts: $(comma_list "${CONFLICTS[@]}")
Replaces: $(comma_list "${CONFLICTS[@]}")
License: $LICENSE
Section: net
Architecture: $ARCHITECTURE
Installed-Size: $installed_size
Maintainer: $MAINTAINER
Source: $URL
Description: $DESCRIPTION
EOF
  printf '%s\n' "${CONFFILES[@]}" > "$control/conffiles"
  install -m755 "$PROJECT/release/config/openwrt.prerm" "$control/prerm"
  printf '2.0\n' > "$outer/debian-binary"
  pin_mtimes "$ROOT"
  pin_mtimes "$control"
  tar_gz "$ROOT" . > "$outer/data.tar.gz"
  tar_gz "$control" . > "$outer/control.tar.gz"
  pin_mtimes "$outer"
  tar_gz "$outer" ./debian-binary ./data.tar.gz ./control.tar.gz > "$ASSET.ipk"
  echo "    package: $ASSET.ipk"
}

# apk mkpkg looks owner names up in the root it is given, so it gets a root that
# knows only root. Provided at its version, sing-box makes apk count this package as
# a sing-box and take it in place of the feed's sing-box or sing-box-tiny.
build_apk() {
  local metadata="$ROOT/lib/apk/packages" apk_root="$WORK/apk-root" conffile
  mkdir -p "$metadata" "$apk_root/etc"
  printf 'root:x:%s:%s:root:/root:/sbin/nologin\n' "$(id -u)" "$(id -g)" > "$apk_root/etc/passwd"
  printf 'root:x:%s:root\n' "$(id -g)" > "$apk_root/etc/group"
  printf '%s\n' "${CONFFILES[@]}" > "$metadata/$PACKAGE.conffiles"
  for conffile in "${CONFFILES[@]}"; do
    printf '%s %s\n' "$conffile" "$(sha256sum "$ROOT$conffile" | cut -d' ' -f1)"
  done > "$metadata/$PACKAGE.conffiles_static"
  (cd "$ROOT" && find . -type f -o -type l) | sed 's|^\./|/|' | grep -v '^/lib/apk/packages/' |
    LC_ALL=C sort > "$metadata/$PACKAGE.list"
  chmod 644 "$metadata"/*
  pin_mtimes "$ROOT"
  apk --root "$apk_root" mkpkg \
    --info "name:$PACKAGE" \
    --info "version:$PACKAGE_VERSION" \
    --info "description:$DESCRIPTION" \
    --info "arch:$ARCHITECTURE" \
    --info "license:$LICENSE" \
    --info "origin:$PACKAGE" \
    --info "url:$URL" \
    --info "maintainer:$MAINTAINER" \
    --info "depends:${DEPENDS[*]}" \
    --info "provides:sing-box=$PACKAGE_VERSION" \
    --info "replaces:${CONFLICTS[*]}" \
    --info "provider-priority:100" \
    --script "post-install:$PROJECT/release/config/openwrt.postinst" \
    --script "post-upgrade:$PROJECT/release/config/openwrt.postinst" \
    --script "pre-deinstall:$PROJECT/release/config/openwrt.prerm" \
    --files "$ROOT" \
    --output "$ASSET.apk"
  rm -rf "$metadata"
  echo "    package: $ASSET.apk"
}

mkdir -p "$OUTPUT"
[ "$FORMAT" = apk ] || build_ipk
[ "$FORMAT" = ipk ] || build_apk
