#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds zond.exe and the Windows installer from a Unix host, with MinGW-w64
# and NSIS (`brew install mingw-w64 makensis`, or `apt install mingw-w64 nsis`)
# and the `x86_64-pc-windows-gnu` Rust target.
#
# The binary links against Npcap's wpcap.dll. Its import library is generated
# here from the functions the `pcap` crate declares, so the Npcap SDK is not
# needed to build; Npcap itself is needed to run, and the installer says so.
#
# Output: target/windows/zond.exe and target/windows/zond-<version>-setup.exe.
set -euo pipefail

cd "$(dirname "$0")/.."
out="target/windows"
lib="$out/lib"
mkdir -p "$lib"

version="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"
pcap="$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "pcap") | .manifest_path' | xargs dirname)"

{
  echo "LIBRARY wpcap.dll"
  echo "EXPORTS"
  grep -o 'fn pcap_[a-zA-Z_0-9]*' "$pcap/src/raw.rs" | sort -u | sed 's/fn /    /'
} > "$lib/wpcap.def"
x86_64-w64-mingw32-dlltool -d "$lib/wpcap.def" -l "$lib/libwpcap.a" -D wpcap.dll

# Npcap is libpcap 1.10; without the version the crate assumes the oldest it
# supports and leaves out calls such as immediate mode.
LIBPCAP_LIBDIR="$PWD/$lib" LIBPCAP_VER=1.10.4 \
  cargo build --release --target x86_64-pc-windows-gnu

x86_64-w64-mingw32-strip -o "$out/zond.exe" target/x86_64-pc-windows-gnu/release/zond.exe
cp LICENSE "$out/LICENSE.txt"
cp windows/README.txt "$out/README.txt"

# makensis aborts on every script without a UTF-8 locale.
LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
  makensis -V2 -DVERSION="$version" -DDIST="$PWD/$out" windows/installer.nsi

echo "$out/zond-$version-setup.exe"
