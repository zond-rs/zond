#!/bin/sh
# Regenerates ubuntu.bin, the Ubuntu security data a release build carries,
# from Canonical's current feeds. Run before a release from the repository
# root, with the engine checked out beside it:
#
#   sh assets/advisories/refresh.sh
#
# It builds zond in release mode and runs `zond update` into a scratch cache,
# so the snapshot is converted by exactly the code that converts a user's.
set -eu
cache="$(mktemp -d)"
trap 'rm -rf "$cache"' EXIT
cargo build --release --quiet
XDG_CACHE_HOME="$cache" ./target/release/zond update
cp "$cache/zond/derived/advisories/ubuntu/data" assets/advisories/ubuntu.bin
echo "assets/advisories/ubuntu.bin: $(wc -c < assets/advisories/ubuntu.bin | tr -d ' ') bytes"
