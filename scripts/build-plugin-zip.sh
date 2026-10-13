#!/usr/bin/env bash
# Package the plugin runtime files only (exclude GitHub docs and build utilities).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-$repo_root/dist/oneclicky-temporary-access.zip}"
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
mkdir -p "$(dirname "$output")"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
plugin_dir="$temp_dir/oneclicky-temporary-access"
mkdir -p "$plugin_dir"

for file in LICENSE.txt index.php oneclicky-temporary-access.php readme.txt uninstall.php; do
  cp "$repo_root/$file" "$plugin_dir/$file"
done
for dir in assets includes languages; do
  cp -R "$repo_root/$dir" "$plugin_dir/$dir"
done

rm -f "$output"
(
  cd "$temp_dir"
  zip -q -r "$output" oneclicky-temporary-access
)
echo "Built: $output"
