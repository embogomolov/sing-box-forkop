#!/usr/bin/env bash
# Builds sing-box-forkop, the sing-box core Forkop runs on OpenWrt, and packages
# it for opkg (.ipk) and apk (.apk). The same script builds the releases in CI.
# See README.md for the variants and the tags.
set -euo pipefail
umask 022

PROJECT=$(cd "$(dirname "$0")" && pwd)
BUILD_CACHE="${FORKOP_BUILD_CACHE:-$HOME/.cache/sing-box-forkop}"
CRONET_GO_PATH="${CRONET_GO_PATH:-$BUILD_CACHE/cronet-go}"

TARGETS=(amd64 arm64 386 armv7 mipsle)
VARIANTS=(base full)

# Every build: the code a build without one of these would need is pruned
# (release/forkop/prune.list). Forkop runs its dashboard, groups, latency tests and nft
# subnet sync through the Clash API and dials Reality and TLS fingerprints through uTLS;
# badlinkname and tfogo_checklinkname0 let the linker accept the go:linkname references
# the dependencies make.
REQUIRED_TAGS=(with_clash_api with_utls badlinkname tfogo_checklinkname0)
# What a build may leave out: Forkop reads the tags of the installed core and refuses
# what it lacks. The full variant carries all of them.
OPTIONAL_TAGS=(
  with_gvisor with_quic with_wireguard with_openvpn with_trusttunnel
  with_vmess with_snell with_ssh with_shadowtls with_tor with_anytls
  with_tailscale with_naive_outbound with_openconnect with_mieru
)
BASE_TAGS=(
  with_gvisor with_quic with_wireguard with_openvpn with_trusttunnel
  with_vmess with_anytls
)
# Forkop runs these tunnels on gVisor's network stack.
GVISOR_TAGS=(with_wireguard with_openvpn with_openconnect with_tailscale)

usage() {
  cat <<'EOF'
Usage: ./build.sh [options] [target...]

Build sing-box-forkop packages for OpenWrt.

Targets:
  amd64 arm64 386 armv7 mipsle         all of them when none is given

Options:
  -v, --variant NAME     base (the default) or full
  -t, --tags LIST        a custom build, the required tags always in it:
                           with_quic,with_openvpn,...   exactly these optional tags
                           +with_openconnect,-with_quic   the variant changed
  -a, --arch LIST        package only for these OpenWrt architectures, for
                         example aarch64_cortex-a53; the target follows from it
  -f, --format FORMAT    ipk, apk or all (the default)
  -V, --version VERSION  package version (derived from the git tags by default)
  -o, --output DIR       where the packages go (dist by default)
      --binary-only      build the binary, skip the packages
  -l, --list             print the variants with their tags, and the targets
      --print-tags       print the tags the other options select, and exit
      --print-required-tags  print the tags every build carries, and exit
      --print-targets    print the targets the other options select, and exit
      --print-go-env     print each selected target with its Go settings, and exit
      --print-variants   print the variant names, and exit
      --fetch-cronet     fetch the cronet source the full variant links, and exit
  -h, --help             print this help

Examples:
  ./build.sh --arch aarch64_cortex-a53
  ./build.sh --variant full arm64 mipsle
  ./build.sh --tags +with_openconnect arm64
EOF
}

die() {
  printf 'build.sh: %s\n' "$*" >&2
  exit 2
}

# The OpenWrt architectures a Go target runs on, and the Go settings for it.
target_architectures() {
  case "$1" in
    amd64) echo "x86_64" ;;
    arm64) echo "aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic" ;;
    386) echo "i386_pentium4" ;;
    armv7) echo "arm_cortex-a5_vfpv4 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4" ;;
    mipsle) echo "mipsel_24kc mipsel_74kc mipsel_mips32" ;;
    *) return 1 ;;
  esac
}

target_go_env() {
  case "$1" in
    amd64) echo "GOARCH=amd64 GOAMD64=v1" ;;
    arm64) echo "GOARCH=arm64" ;;
    386) echo "GOARCH=386 GO386=sse2" ;;
    armv7) echo "GOARCH=arm GOARM=7" ;;
    mipsle) echo "GOARCH=mipsle GOMIPS=softfloat" ;;
  esac
}

naive_arch() {
  case "$1" in
    armv7) echo arm ;;
    *) echo "$1" ;;
  esac
}

target_of_architecture() {
  local target architecture
  for target in "${TARGETS[@]}"; do
    for architecture in $(target_architectures "$target"); do
      [ "$architecture" != "$1" ] || { echo "$target"; return 0; }
    done
  done
  return 1
}

variant_tags() {
  local -a tags
  case "$1" in
    base) tags=("${BASE_TAGS[@]}") ;;
    full) tags=("${OPTIONAL_TAGS[@]}") ;;
    *) return 1 ;;
  esac
  sorted_list "${REQUIRED_TAGS[@]}" "${tags[@]}"
}

sorted_list() {
  printf '%s\n' "$@" | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -
}

contains() {
  local item="$1"
  shift
  printf '%s\n' "$@" | grep -qxF -- "$item"
}

# A required tag is in every build already; an optional one is added or removed.
# Any other name would select code this tree does not have.
resolve_tags() {
  local spec="$1" variant="$2" item name tag changes=0 exact=0
  local -a tags=() requested=() kept=()
  IFS=',' read -r -a requested <<< "$(tr -d '[:space:]' <<< "$spec")"
  for item in "${requested[@]}"; do
    case "$item" in
      '') ;;
      [+-]*) changes=1 ;;
      *) exact=1 ;;
    esac
  done
  [ $((changes + exact)) -gt 0 ] || die "--tags is empty"
  [ $((changes + exact)) -eq 1 ] || die "--tags takes either a list of tags or +tag/-tag changes, not both: $spec"

  if [ "$changes" = 1 ]; then
    IFS=',' read -r -a tags <<< "$(variant_tags "$variant")"
  fi
  for item in "${requested[@]}"; do
    [ -n "$item" ] || continue
    name="${item#[+-]}"
    if contains "$name" "${REQUIRED_TAGS[@]}"; then
      [ "${item:0:1}" != - ] || die "$name cannot be removed: every build carries it, and the code a build without it would need is pruned"
      continue
    fi
    contains "$name" "${OPTIONAL_TAGS[@]}" ||
      die "unknown tag '$name'. A build chooses among: ${OPTIONAL_TAGS[*]}"
    case "$item" in
      -*)
        kept=()
        for tag in "${tags[@]}"; do
          [ "$tag" = "$name" ] || kept+=("$tag")
        done
        tags=("${kept[@]}")
        ;;
      *) tags+=("$name") ;;
    esac
  done
  if ! contains with_gvisor "${tags[@]}"; then
    for tag in "${GVISOR_TAGS[@]}"; do
      if contains "$tag" "${tags[@]}"; then
        die "$tag needs with_gvisor: Forkop runs WireGuard, AmneziaWG, WARP, OpenVPN, OpenConnect and Tailscale on gVisor's network stack"
      fi
    done
  fi
  sorted_list "${REQUIRED_TAGS[@]}" "${tags[@]}"
}

# The name a tag set is published under: an official variant when the set is
# exactly one, "custom" otherwise.
variant_label() {
  local variant
  for variant in "${VARIANTS[@]}"; do
    [ "$1" != "$(variant_tags "$variant")" ] || { echo "$variant"; return; }
  done
  echo custom
}

list_variants() {
  local variant target
  for variant in "${VARIANTS[@]}"; do
    printf '%s\n  %s\n' "$variant" "$(variant_tags "$variant" | sed 's/,/ /g')"
  done
  printf '\nrequired in every build\n  %s\n' "${REQUIRED_TAGS[*]}"
  printf 'optional\n  %s\n  %s need with_gvisor\n' "${OPTIONAL_TAGS[*]}" "${GVISOR_TAGS[*]}"
  printf '\ntargets\n'
  for target in "${TARGETS[@]}"; do
    printf '  %-7s %s\n' "$target" "$(target_architectures "$target")"
  done
}

# X.Y.Z-rN at a release tag vX.Y.Z-rN. Between releases X.Y.Z-rN+K, K commits
# after the last release, or X.Y.Z-r0+K before the first release on the upstream
# release X.Y.Z merged last, so every build sorts above the release before it and
# below the next.
version_from_git() {
  local exact release base count
  if exact=$(git -C "$PROJECT" describe --tags --exact-match --match 'v*-r[0-9]*' 2>/dev/null); then
    printf '%s\n' "${exact#v}"
    return
  fi
  release=$(git -C "$PROJECT" describe --tags --abbrev=0 --match 'v*-r[0-9]*' 2>/dev/null || true)
  base=$(git -C "$PROJECT" describe --tags --abbrev=0 --match 'v[0-9]*' --exclude 'v*-*' 2>/dev/null || true)
  if [ -n "$release" ] && { [ -z "$base" ] || [ "${release%-r*}" = "$base" ]; }; then
    count=$(git -C "$PROJECT" rev-list --count "$release..HEAD")
    printf '%s+%s\n' "${release#v}" "$count"
    return
  fi
  [ -n "$base" ] ||
    die "cannot derive the version: neither a vX.Y.Z-rN release tag nor an upstream vX.Y.Z tag is reachable. Fetch the tags or pass --version"
  count=$(git -C "$PROJECT" rev-list --count "$base..HEAD")
  printf '%s-r0+%s\n' "${base#v}" "$count"
}

require_tools() {
  local tool missing=()
  local -a tools=(go git tar gzip sha256sum flock)
  [ "$BINARY_ONLY" = 1 ] || [ "$PACKAGE_FORMAT" = ipk ] || tools+=(apk)
  for tool in "${tools[@]}"; do
    command -v "$tool" >/dev/null || missing+=("$tool")
  done
  [ "${#missing[@]}" = 0 ] || die "missing required tools: ${missing[*]}. README.md lists what to install"
}

# A checkout made with core.autocrlf=true before .gitattributes asked for LF
# still holds CRLF files, and Go would build the carriage returns into the
# binary's raw strings.
require_lf_checkout() {
  local crlf
  crlf=$(git -C "$PROJECT" ls-files --eol -- '*.go' 2>/dev/null | awk '$2 == "w/crlf" || $2 == "w/mixed" { n++ } END { print n + 0 }')
  [ "$crlf" = 0 ] || die "$crlf Go files in this checkout have CRLF line endings, and a build from it differs from everyone else's. Check it out again: git rm -rq --cached . && git reset -q --hard"
}

acquire_build_lock() {
  mkdir -p "$BUILD_CACHE"
  exec 9>"$BUILD_CACHE/build.lock"
  if ! flock -n 9; then
    echo "build.sh: another sing-box-forkop build is using $BUILD_CACHE. Wait for it to finish." >&2
    exit 75
  fi
}

ensure_cronet_go() {
  local revision marker keyring
  revision=$(tr -d '[:space:]' < "$PROJECT/.github/CRONET_GO_VERSION")
  if [ ! -d "$CRONET_GO_PATH/.git" ]; then
    mkdir -p "$CRONET_GO_PATH"
    git -C "$CRONET_GO_PATH" init -q
    git -C "$CRONET_GO_PATH" remote add origin https://github.com/sagernet/cronet-go.git
  fi
  if [ "$(git -C "$CRONET_GO_PATH" rev-parse HEAD 2>/dev/null || true)" != "$revision" ]; then
    echo "==> Fetching cronet-go $revision"
    git -C "$CRONET_GO_PATH" fetch --depth=1 origin "$revision"
    git -C "$CRONET_GO_PATH" checkout -q --detach FETCH_HEAD
  fi
  git -C "$CRONET_GO_PATH" submodule update --init --recursive --depth=1

  marker="$CRONET_GO_PATH/.forkop-keyring-$revision"
  keyring="$CRONET_GO_PATH/naiveproxy/src/build/linux/sysroot_scripts/keyring.gpg"
  if [ ! -e "$marker" ]; then
    rm -f "$keyring"
    (cd "$CRONET_GO_PATH" && GPG_TTY=/dev/null ./naiveproxy/src/build/linux/sysroot_scripts/generate_keyring.sh)
    touch "$marker"
  fi
}

# The C toolchain cronet is built with, as the environment the cgo build needs.
naive_environment() {
  local arch="$1"
  (cd "$CRONET_GO_PATH" && go run ./cmd/build-naive --target="linux/$arch" --libc=musl download-toolchain) >&2
  (cd "$CRONET_GO_PATH" && go run ./cmd/build-naive --target="linux/$arch" --libc=musl env) |
    grep -E '^[A-Za-z_][A-Za-z0-9_]*='
}

build_binary() {
  local target="$1" build_tags="$2" binary="$3" ldflags variable
  local -a build_env=(GOOS=linux "GOTOOLCHAIN=$GO_TOOLCHAIN") go_env
  read -r -a go_env <<< "$(target_go_env "$target")"
  build_env+=("${go_env[@]}")
  if [[ ",$build_tags," == *,with_naive_outbound,* ]]; then
    build_tags="$build_tags,with_musl"
    while IFS= read -r variable; do
      build_env+=("$variable")
    done < <(naive_environment "$(naive_arch "$target")")
    build_env+=(CGO_ENABLED=1)
  else
    build_env+=(CGO_ENABLED=0)
  fi
  ldflags="-X github.com/sagernet/sing-box/constant.Version=$VERSION $(tr '\n' ' ' < "$PROJECT/release/LDFLAGS") -s -w -buildid="
  mkdir -p "$(dirname "$binary")"
  # The version is stamped above; Go's VCS stamp would make two checkouts of one commit build
  # different binaries.
  (cd "$PROJECT" && env "${build_env[@]}" go build -trimpath -buildvcs=false -tags "$build_tags" -ldflags "$ldflags" -o "$binary" ./cmd/sing-box)
}

build_target() {
  local target="$1" label binary architecture architectures
  label=$(variant_label "$TAGS")
  binary="$OUTPUT/build/$target/$label/sing-box"
  architectures=$(target_architectures "$target")
  [ -z "$ARCHITECTURES" ] || architectures=$(for architecture in $ARCHITECTURES; do
    [ "$(target_of_architecture "$architecture")" != "$target" ] || echo "$architecture"
  done)

  echo "==> Building $target $label ($VERSION)"
  echo "    tags: $TAGS"
  build_binary "$target" "$TAGS" "$binary"
  echo "    binary: $binary ($(stat -c %s "$binary") bytes)"
  [ "$BINARY_ONLY" = 0 ] || return 0
  for architecture in $architectures; do
    bash "$PROJECT/release/forkop/package.sh" \
      --binary "$binary" --arch "$architecture" --version "$VERSION" \
      --variant "$label" --format "$PACKAGE_FORMAT" --output "$OUTPUT"
  done
}

VARIANT=base
TAGS_SPEC=""
ARCHITECTURES=""
PACKAGE_FORMAT=all
VERSION=""
OUTPUT="$PROJECT/dist"
BINARY_ONLY=0
ACTION=build
SELECTED=()

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--variant) [ $# -ge 2 ] || die "$1 needs a value"; VARIANT="$2"; shift 2 ;;
    -t|--tags) [ $# -ge 2 ] || die "$1 needs a value"; TAGS_SPEC="$2"; shift 2 ;;
    -a|--arch) [ $# -ge 2 ] || die "$1 needs a value"; ARCHITECTURES="${2//,/ }"; shift 2 ;;
    -f|--format) [ $# -ge 2 ] || die "$1 needs a value"; PACKAGE_FORMAT="$2"; shift 2 ;;
    -V|--version) [ $# -ge 2 ] || die "$1 needs a value"; VERSION="$2"; shift 2 ;;
    -o|--output) [ $# -ge 2 ] || die "$1 needs a value"; OUTPUT="$2"; shift 2 ;;
    --binary-only) BINARY_ONLY=1; shift ;;
    -l|--list) list_variants; exit 0 ;;
    --print-tags) ACTION=print-tags; shift ;;
    --print-required-tags) sorted_list "${REQUIRED_TAGS[@]}"; exit 0 ;;
    --print-targets) ACTION=print-targets; shift ;;
    --print-go-env) ACTION=print-go-env; shift ;;
    --print-variants) echo "${VARIANTS[*]}"; exit 0 ;;
    --fetch-cronet) ACTION=fetch-cronet; shift ;;
    -h|--help) usage; exit 0 ;;
    all) SELECTED+=("${TARGETS[@]}"); shift ;;
    -*) die "unknown option $1. Run ./build.sh --help" ;;
    *) SELECTED+=("$1"); shift ;;
  esac
done

variant_tags "$VARIANT" >/dev/null || die "unknown variant '$VARIANT': choose one of ${VARIANTS[*]}"
[[ "$PACKAGE_FORMAT" =~ ^(all|ipk|apk)$ ]] || die "unknown format '$PACKAGE_FORMAT': choose ipk, apk or all"
for target in "${SELECTED[@]}"; do
  target_architectures "$target" >/dev/null || die "unknown target '$target': choose from ${TARGETS[*]}"
done
if [ -n "$ARCHITECTURES" ]; then
  arch_targets=()
  for architecture in $ARCHITECTURES; do
    target=$(target_of_architecture "$architecture") ||
      die "no target builds for OpenWrt architecture '$architecture'. Run ./build.sh --list"
    arch_targets+=("$target")
  done
  [ "${#SELECTED[@]}" = 0 ] || [ "$(sorted_list "${SELECTED[@]}")" = "$(sorted_list "${arch_targets[@]}")" ] ||
    die "--arch $ARCHITECTURES builds $(sorted_list "${arch_targets[@]}"); leave the targets out or name the same ones"
  SELECTED=("${arch_targets[@]}")
fi
[ "${#SELECTED[@]}" -gt 0 ] || SELECTED=("${TARGETS[@]}")
read -r -a SELECTED <<< "$(printf '%s\n' "${SELECTED[@]}" | awk '!seen[$0]++' | paste -sd' ' -)"
if [ "$ACTION" = print-targets ]; then
  echo "${SELECTED[*]}"
  exit 0
fi
if [ "$ACTION" = print-go-env ]; then
  for target in "${SELECTED[@]}"; do
    echo "$target $(target_go_env "$target")"
  done
  exit 0
fi

if [ -n "$TAGS_SPEC" ]; then
  TAGS=$(resolve_tags "$TAGS_SPEC" "$VARIANT")
else
  TAGS=$(variant_tags "$VARIANT")
fi
if [ "$ACTION" = print-tags ]; then
  echo "$TAGS"
  exit 0
fi
if [ "$ACTION" = fetch-cronet ]; then
  acquire_build_lock
  ensure_cronet_go
  exit 0
fi
[ -n "$VERSION" ] || VERSION=$(version_from_git)
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z._+~-]*$ ]] || die "invalid version '$VERSION'"
OUTPUT=$(mkdir -p "$OUTPUT" && cd "$OUTPUT" && pwd)

require_tools
require_lf_checkout
# The toolchain is pinned here, not taken from go.mod's minimum: the runtime decides how the
# core uses memory on a router, and every measurement was made with this one.
GO_TOOLCHAIN="go$(tr -d '[:space:]' < "$PROJECT/release/forkop/GO_VERSION")"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$PROJECT" log -1 --format=%ct 2>/dev/null) ||
    die "cannot read the commit time the packages are dated with: build from a git checkout or set SOURCE_DATE_EPOCH"
fi
export SOURCE_DATE_EPOCH
acquire_build_lock
[[ ",$TAGS," != *,with_naive_outbound,* ]] || ensure_cronet_go

for target in "${SELECTED[@]}"; do
  build_target "$target"
done
