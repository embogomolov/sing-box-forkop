#!/usr/bin/env bash
# Checks what upstream merges and hand edits can silently break: no path of
# release/forkop/prune.list is back, every row of third_party/README.md matches
# go.mod (the version upstream requires and the replace into third_party), every
# Go file and package outside third_party is built by a stock build, every
# package of a third_party module is linked by one or needed by its tests, and
# the linker still drops the methods no build calls.
# Exits 1 with one line per problem.
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

# A stock build is a variant, or the least a custom build can be (the required tags
# alone), on one of the targets, with the pinned Go or a later one, so a file that
# switches on with a newer toolchain stays. A file none of them compiles, or a package
# no binary links and no other package's test imports, is code nobody ships or tests.
module=$(go list -m)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go_minor=$(sed -E 's/^1\.([0-9]+).*/\1/' release/forkop/GO_VERSION)
later_go=$(seq $((go_minor + 1)) $((go_minor + 8)) | sed 's/^/go1./' | paste -sd, -)
list_pass() {
    local tags="$1" cgo="$2" out
    shift 2
    out=$(mktemp "$work/pass.XXXXXX")
    env GOOS=linux CGO_ENABLED="$cgo" "$@" go list -e -deps -tags "$tags" -f '{{.ImportPath}}' ./cmd/sing-box \
        > "$(mktemp "$work/deps.XXXXXX")"
    env GOOS=linux CGO_ENABLED="$cgo" "$@" go list -e -tags "$tags" -f \
        '{{$dir := .Dir}}{{$path := .ImportPath}}P {{$path}}{{range .Imports}} {{.}}{{end}}
{{range .IgnoredGoFiles}}F {{$dir}}/{{.}}
{{end}}T{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}}{{if ne . $path}} {{.}}{{end}}{{end}}' \
        ./... > "$out"
}
pids=()
for variant in $(bash build.sh --print-variants) required; do
    if [ "$variant" = required ]; then
        tags=$(bash build.sh --print-required-tags)
    else
        tags=$(bash build.sh --variant "$variant" --print-tags)
    fi
    cgo=0
    [[ ",$tags," != *,with_naive,* ]] || cgo=1
    while read -r _ goenv; do
        # shellcheck disable=SC2086
        list_pass "$tags" "$cgo" $goenv &
        pids+=("$!")
    done < <(bash build.sh --print-go-env)
    list_pass "$tags,$later_go" "$cgo" GOARCH=amd64 &
    pids+=("$!")
    env GOOS=linux GOARCH=amd64 CGO_ENABLED="$cgo" go list -e -deps -test -tags "$tags" -f '{{.ImportPath}}' ./... \
        > "$(mktemp "$work/deps.XXXXXX")" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid" || { problem "go list failed, the build check did not run"; exit 1; }
done
passes=$(find "$work" -name 'pass.*' | wc -l)

root="$PWD/"
awk -v passes="$passes" -v root="$root" '
    $1 == "F" { file = substr($0, 3); sub("^" root, "", file); ignored[file]++ }
    END { for (file in ignored) if (ignored[file] == passes) print file }
' "$work"/pass.* | LC_ALL=C sort > "$work/never-compiled"
while read -r file; do
    problem "no stock build compiles $file: prune it or drop it"
done < "$work/never-compiled"

awk -v module="$module" -v main="$module/cmd/sing-box" '
    FNR == 1 { pass++ }
    $1 == "P" { packages[$2] = 1; for (i = 3; i <= NF; i++) if ($i == module || index($i, module "/") == 1) edge[pass, $2, ++count[pass, $2]] = $i }
    $1 == "T" { for (i = 2; i <= NF; i++) if ($i == module || index($i, module "/") == 1) used[$i] = 1 }
    END {
        for (p = 1; p <= pass; p++) {
            delete seen
            stack[1] = main; depth = 1; seen[main] = 1
            while (depth > 0) {
                current = stack[depth--]
                used[current] = 1
                for (i = 1; i <= count[p, current]; i++) {
                    next_package = edge[p, current, i]
                    if (!(next_package in seen)) { seen[next_package] = 1; stack[++depth] = next_package }
                }
            }
        }
        for (package in packages) if (!(package in used)) print package
    }
' "$work"/pass.* | LC_ALL=C sort > "$work/unlinked"
while read -r package; do
    problem "no stock build links $package and no other package tests import it: prune it or drop it"
done < "$work/unlinked"

# A third_party module carries the packages a stock build links, the ones the
# core's tests import and what their own tests need; prune.list drops the rest.
sed 's/ \[.*//; s/\.test$//' "$work"/deps.* | LC_ALL=C sort -u > "$work/linked"
for dir in third_party/*/; do
    name=$(basename "$dir")
    path=$(cd "$dir" && go list -m)
    pattern="^$(printf '%s' "$path" | sed 's/[.]/\\./g')(/|\$)"
    mapfile -t kept < <(grep -E "$pattern" "$work/linked" || true)
    if [ "${#kept[@]}" -eq 0 ]; then
        problem "no stock build links anything of third_party/$name"
        continue
    fi
    (cd "$dir" && GOOS=linux go list -e -deps -test -f '{{.ImportPath}}' "${kept[@]}") |
        sed 's/ \[.*//; s/\.test$//' | LC_ALL=C sort -u > "$work/needed.$name"
    (cd "$dir" && GOOS=linux go list -e -f '{{.ImportPath}}' ./...) | LC_ALL=C sort -u > "$work/all.$name"
    while read -r package; do
        problem "no stock build links $package and no kept package's tests need it: list third_party/$name${package#"$path"} in release/forkop/prune.list"
    done < <(LC_ALL=C comm -23 "$work/all.$name" "$work/needed.$name")
done

# A reachable function that looks a method up by an index or a computed name makes the
# linker keep every exported method of every reachable type, megabytes no build runs.
tags=$(bash build.sh --variant full --tags -with_naive --print-tags)
if env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "$tags" -ldflags "-checklinkname=0 -dumpdep" \
    -o /dev/null ./cmd/sing-box 2> "$work/dumpdep"; then
    while read -r function; do
        problem "the linker keeps every exported method: $function looks methods up through reflect (go build -ldflags=-dumpdep shows what reaches it)"
    done < <(grep -o '[^ ]* <ReflectMethod>' "$work/dumpdep" | sed 's/ <ReflectMethod>$//' | LC_ALL=C sort -u)
else
    problem "go build -ldflags=-dumpdep failed, the method pruning check did not run"
fi

[ "$problems" -eq 0 ]
