#!/usr/bin/env bash
# Checks what upstream merges and hand edits can silently break: no path of
# release/forkop/prune.list is back, and every row of third_party/README.md
# matches go.mod (the version upstream requires and the replace into
# third_party). Exits 1 with one line per problem.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
problems=0
problem() {
    printf 'check-tree.sh: %s\n' "$*" >&2
    problems=$((problems + 1))
}

mapfile -t paths < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' release/forkop/prune.list | grep -v '^$')
for path in "${paths[@]}"; do
    if [ -n "$(git ls-files -- "$path" | head -n 1)" ]; then
        problem "pruned path is back: $path (run release/forkop/prune.sh)"
    fi
done

while IFS='|' read -r _ name module version _; do
    name=$(printf '%s' "$name" | tr -d ' ')
    module=$(printf '%s' "$module" | tr -d ' ')
    version=$(printf '%s' "$version" | tr -d ' ')
    [ -d "third_party/$name" ] || problem "third_party/$name is missing"
    required=$(awk -v module="$module" '$1 == module && $2 ~ /^v/ { print $2 }' go.mod | head -n 1)
    [ "$required" = "$version" ] || problem "go.mod requires $module $required, third_party/$name is $version (run release/forkop/third-party.sh $name $required)"
    grep -q "^replace $module => ./third_party/$name\$" go.mod || problem "go.mod does not replace $module with ./third_party/$name"
done < <(grep -E '^[|] [a-z][a-z0-9-]* [|] ' third_party/README.md)

[ "$problems" -eq 0 ]
