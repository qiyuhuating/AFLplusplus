#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

case $(uname -s) in
  Linux) ;;
  *) echo "[*] SymQEMU callback tests require Linux; skipping"; exit 0 ;;
esac

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# Call the real callbacks; no SymQEMU installation or instrumented target needed.
${CC:-cc} ${CFLAGS:-} -UNDEBUG -O1 -g \
  -fno-omit-frame-pointer -ffunction-sections -fdata-sections \
  -I"$ROOT/include" "$ROOT/test/test-symqemu-scandir.c" \
  -Wl,--gc-sections -o "$WORK/test-symqemu-scandir"

for mode in success empty count read-error open-error scan-error; do
  mkdir "$WORK/$mode"
  "$WORK/test-symqemu-scandir" "$mode" "$WORK/$mode"
  echo "[+] SymQEMU scandir $mode: passed"
done
