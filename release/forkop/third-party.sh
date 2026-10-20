#!/usr/bin/env bash
# Moves third_party/<name> to another version of its module. The change between
# the two pristine module trees, less the paths release/forkop/prune.list drops,
# is applied three-way, so the commits on top of the old version stay on top of
# the new one; a conflict is left in the tree for you to resolve. The table in
# third_party/README.md is updated; commit the result as one change once the
# module's own tests and the core's pass.
#
#   release/forkop/third-party.sh wireguard-go v0.0.9-0.20261101000000-abcdef123456
set -euo pipefail

die() {
    printf 'third-party.sh: %s\n' "$*" >&2
    exit 1
}

[ $# -eq 2 ] || { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's|^# \{0,1\}||'; exit 2; }
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
NAME=$1
VERSION=$2
ROW=$(grep "^| $NAME |" third_party/README.md) || die "third_party/README.md has no row for $NAME"
MODULE=$(printf '%s' "$ROW" | awk -F'|' '{gsub(/ /, "", $3); print $3}')
OLD=$(printf '%s' "$ROW" | awk -F'|' '{gsub(/ /, "", $4); print $4}')
[ "$OLD" != "$VERSION" ] || die "$NAME is already at $VERSION"

module_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\": \"\(.*\)\",\{0,1\}$/\1/p" | head -n 1 | sed 's|\\\\|/|g'
}
OLD_JSON=$(GOFLAGS=-mod=mod go mod download -json "$MODULE@$OLD")
NEW_JSON=$(GOFLAGS=-mod=mod go mod download -json "$MODULE@$VERSION")
OLD_DIR=$(module_field "$OLD_JSON" Dir)
NEW_DIR=$(module_field "$NEW_JSON" Dir)
NEW_SUM=$(module_field "$NEW_JSON" Sum)
[ -d "$OLD_DIR" ] && [ -d "$NEW_DIR" ] || die "cannot download $MODULE at $OLD or $VERSION"

WORK=$(mktemp -d)
trap 'chmod -R u+w "$WORK"; rm -rf "$WORK"' EXIT
cp -r "$OLD_DIR" "$WORK/old"
cp -r "$NEW_DIR" "$WORK/new"
chmod -R u+w "$WORK"
while IFS= read -r path; do
    relative=${path#third_party/$NAME/}
    [ -n "$relative" ] && [ "$relative" != "$path" ] || continue
    rm -rf "${WORK:?}/old/$relative" "${WORK:?}/new/$relative"
done < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' release/forkop/prune.list | grep "^third_party/$NAME/" || true)
(cd "$WORK" && git diff --no-index --binary old new > change.patch) || true
if [ -s "$WORK/change.patch" ]; then
    git apply -3 -p2 --directory="third_party/$NAME" "$WORK/change.patch" ||
        printf 'third-party.sh: conflicts left in third_party/%s, resolve them before committing\n' "$NAME" >&2
fi
sed -i "s#^| $NAME | $MODULE | $OLD | [^|]* |#| $NAME | $MODULE | $VERSION | $NEW_SUM |#" third_party/README.md
printf '%s: %s -> %s (%s)\n' "$NAME" "$OLD" "$VERSION" "$NEW_SUM"
