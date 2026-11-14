#!/bin/sh
# Reproducible build of sentinel-se-helper. Usage: build.sh <output-path>
# Requires: macOS 14+ on Apple silicon or a T2 Mac, Xcode command-line tools (swiftc).
# Prints the SHA-256 of the binary; that value is what an operator pins in policy (contract §6).
set -eu
out="${1:?usage: build.sh <output-path>}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$(dirname "$out")"
xcrun swiftc -O -swift-version 5 -target "$(uname -m)-apple-macosx14.0" \
  -framework CryptoKit -framework LocalAuthentication -framework Security \
  -o "$out" "$here/main.swift"
codesign --force --sign - --timestamp=none "$out" 2>/dev/null
shasum -a 256 "$out" | cut -d' ' -f1
