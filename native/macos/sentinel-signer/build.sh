#!/bin/sh
# Build sentinel-signer ON THE SIGNING DEVICE (design §7, round 2 §5). Usage: build.sh <output-path>
# Requires: macOS 14+ on Apple silicon or a Touch ID Mac, Xcode command-line tools. Run with the network off.
# The signer's own test suite runs first; a failure stops the build. Prints the SHA-256 to record in the
# SD log. The DM never supplies a binary: this script builds from reviewed source only.
# The TEST-ONLY `signer-interop` product is never built or installed by this script.
set -eu
out="${1:?usage: build.sh <output-path>}"
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
swift test
swift build -c release --product sentinel-signer
bin="$(swift build -c release --show-bin-path)/sentinel-signer"
mkdir -p "$(dirname "$out")"
cp "$bin" "$out"
codesign --force --sign - --timestamp=none "$out" 2>/dev/null
shasum -a 256 "$out" | cut -d' ' -f1
