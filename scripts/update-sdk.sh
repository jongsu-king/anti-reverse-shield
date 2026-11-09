#!/bin/sh
# Download the latest anti-reverse-shield native SDK for this OS/CPU, verify it
# against the release's SHA256SUMS.txt and unpack it into a vendor folder.
#
#   scripts/update-sdk.sh [--check] [--dir third_party/anti-reverse-shield]
#
# --check   only compare; exit 10 if a newer release exists (handy in CI/cron)
# The installed version is recorded in <dir>/VERSION. Needs curl, tar, and
# sha256sum or shasum.
set -eu
REPO="jongsu-king/anti-reverse-shield"
DIR="third_party/anti-reverse-shield"
CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --dir) DIR="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=macos ;; *) echo "use update-sdk.ps1 on Windows" >&2; exit 2 ;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=x86_64 ;; esac

JSON=$(curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/releases/latest")
TAG=$(printf '%s' "$JSON" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
VERSION=${TAG#v}
CURRENT=$(cat "$DIR/VERSION" 2>/dev/null || echo none)
echo "installed: $CURRENT   latest: $VERSION"
if [ "$CURRENT" = "$VERSION" ]; then echo "up to date"; exit 0; fi
if [ "$CHECK" = 1 ]; then echo "a newer SDK is available"; exit 10; fi

NAME="anti-reverse-shield-sdk-$VERSION-$OS-$ARCH.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$NAME" "$BASE/$NAME"
curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt"
EXPECTED=$(grep " $NAME\$" "$TMP/SHA256SUMS.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then ACTUAL=$(sha256sum "$TMP/$NAME" | cut -d' ' -f1)
else ACTUAL=$(shasum -a 256 "$TMP/$NAME" | cut -d' ' -f1); fi
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA-256 of $NAME does not match SHA256SUMS.txt; nothing changed" >&2; exit 1
fi
mkdir -p "$TMP/x" && tar -C "$TMP/x" -xzf "$TMP/$NAME"
SRC=$(find "$TMP/x" -mindepth 1 -maxdepth 1 -type d | head -n 1)
mkdir -p "$(dirname "$DIR")"
rm -rf "$DIR.new" && mv "$SRC" "$DIR.new" && rm -rf "$DIR" && mv "$DIR.new" "$DIR"
echo "$VERSION" > "$DIR/VERSION"
echo "updated $DIR to $VERSION (verified $ACTUAL)"
