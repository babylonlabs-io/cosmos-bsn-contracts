#!/bin/bash
set -o errexit -o nounset -o pipefail
command -v shellcheck >/dev/null && shellcheck "$0"

function print_usage() {
  echo "Usage: $0 [-h|--help] <new_version>"
  echo "e.g.: $0 0.8.0"
}

if [ "$#" -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]
then
    print_usage
    exit 1
fi

# Check repo
SCRIPT_DIR="$(realpath "$(dirname "$0")")"
if [[ "$(realpath "$SCRIPT_DIR/..")" != "$(pwd)" ]]; then
  echo "Script must be called from the repo root"
  exit 2
fi

# Ensure repo is not dirty
CHANGES_IN_REPO=$(git status --porcelain --untracked-files=no)
if [[ -n "$CHANGES_IN_REPO" ]]; then
    echo "Repository is dirty. Showing 'git status' and 'git --no-pager diff' for debugging now:"
    git status && git --no-pager diff
    exit 3
fi

CARGO_TOML="./Cargo.toml"

NEW="$1"
OLD=$(sed -n -e 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$CARGO_TOML")
echo "Updating old version $OLD to new version $NEW ..."

FILES_MODIFIED=()

sed -i -e "s/^version\([[:space:]]*\)=[[:space:]]*\"$OLD\"/version\1= \"$NEW\"/" "$CARGO_TOML"
FILES_MODIFIED+=("$CARGO_TOML")

cargo build
FILES_MODIFIED+=("Cargo.lock")

for CONTRACT in ./contracts/*/; do
  CRATE_NAME=$(basename "$CONTRACT")
  (cd "$CONTRACT" && cargo run --bin "$CRATE_NAME-schema")
  FILES_MODIFIED+=("$CONTRACT"/schema/)
done

echo "Staging ${FILES_MODIFIED[*]} ..."
git add "${FILES_MODIFIED[@]}"
git commit -m "Set version: $NEW"
