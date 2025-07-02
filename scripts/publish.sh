#!/bin/bash
set -o errexit -o nounset -o pipefail
command -v shellcheck >/dev/null && shellcheck "$0"

function print_usage() {
  echo "Usage: $0 [-h|--help]"
  echo "Publishes crates to crates.io."
}

if [ $# = 1 ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ] ; }
then
    print_usage
    exit 1
fi

# These are imported by other packages - wait 30 seconds between each as they have linear dependencies
BASE_CRATES="packages/bitcoin packages/eots packages/merkle packages/proto"

ALL_CRATES="packages/apis packages/test-utils"

SLEEP_TIME=30

for CRATE in $BASE_CRATES; do
  (
    cd "$CRATE"
    echo "Publishing $CRATE"
    cargo publish
    # wait for these to be processed on crates.io
    echo "Waiting for crates.io to recognize $CRATE"
    sleep $SLEEP_TIME
  )
done

for CRATE in $ALL_CRATES; do
  (
    cd "$CRATE"
    echo "Publishing $CRATE"
    cargo publish
  )
done

echo "Everything is published!"
