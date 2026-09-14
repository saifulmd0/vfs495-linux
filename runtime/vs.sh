#!/bin/bash
# Run the unlocked HP validity-sensor tool with the USB logger.
# Only an allowlist of read-only / volatile commands is accepted.
# Usage: sudo ./vs.sh <command> [args...]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OWNER="${SUDO_USER:-$(id -un)}"

case "${1:-}" in
nosuchcommand | getver | getstartinfo | getconfig | sensorstat | sslstat | flashInfo | getfstate | getprint | getprintwait | stopprint)
	;;
*)
	echo "refused: '${1:-}' is not on the allowlist" >&2
	echo "allowed: nosuchcommand getver getstartinfo getconfig sensorstat sslstat flashInfo getfstate getprint stopprint" >&2
	exit 2
	;;
esac

for a in "$@"; do
	case "$a" in
	-sec | -lock)
		echo "refused: option '$a' is not allowed yet" >&2
		exit 2
		;;
	esac
done

OUT="$HERE/../captures/$(date +%Y%m%d-%H%M%S)-$1"
mkdir -p "$OUT"
cd "$OUT"
echo "$*" > cmdline.txt

set +e
VFSLOG="$OUT/usb.log" \
	LD_PRELOAD="$HERE/lib/usblog.so" \
	LD_LIBRARY_PATH="$HERE/lib" \
	timeout 60 "$HERE/bin/validity-sensor-unlocked" "$@" 2>&1 | tee stdout.txt
rc=${PIPESTATUS[0]}
set -e

chown -R "$OWNER": "$OUT"
echo "exit=$rc  capture dir: $OUT"
