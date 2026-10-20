#!/usr/bin/env bash
# Deletes every upstream path listed in release/forkop/prune.list and tidies
# go.mod. Run it right after merging an upstream tag: deleting again resolves
# each conflict over a file upstream changed and this core does not carry, and
# drops what upstream added under a pruned path.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
mapfile -t paths < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' release/forkop/prune.list | grep -v '^$')
git rm -r -q -f --ignore-unmatch -- "${paths[@]}"
for path in "${paths[@]}"; do
    rm -rf -- $path
done
# tidy resolves the imports of every system and tag, and third_party lacks the packages
# no stock build links: -e lets it finish past them.
go mod tidy -e
