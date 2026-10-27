#!/usr/bin/env bash
# Writes release.json and SHA256SUMS beside the packages of one release, the files Forkop's
# install.sh and its Components tab read: release.json names the version, its tag and the oldest
# Forkop the release works with, FORKOP_REQUIRED_VERSION here. INSTALL_COMMAND, when set, goes in
# as install_command: the release installs only with that command, which the tab shows instead.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "Usage: $0 DIRECTORY vX.Y.Z-rN [OWNER/REPOSITORY]" >&2
  exit 2
fi
directory=$1 tag=$2 repository=${3:-ushan0v/sing-box-forkop}
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+$ ]]; then
  echo "$0: $tag is not a vX.Y.Z-rN release tag" >&2
  exit 2
fi
forkop=$(tr -d '[:space:]' < "$(dirname "$0")/FORKOP_REQUIRED_VERSION")
install_command=""
if [ -n "${INSTALL_COMMAND:-}" ]; then
  install_command="${INSTALL_COMMAND//\\/\\\\}"
  install_command=",
  \"install_command\": \"${install_command//\"/\\\"}\""
fi

cat > "$directory/release.json" <<EOF
{
  "schema": 1,
  "name": "sing-box-forkop",
  "version": "${tag#v}",
  "tag": "$tag",
  "page": "https://github.com/$repository/releases/tag/$tag",
  "requires": { "forkop": "$forkop" }${install_command}
}
EOF
cd "$directory"
sha256sum -- *.ipk *.apk release.json > SHA256SUMS
