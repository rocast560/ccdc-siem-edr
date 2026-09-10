#!/bin/bash
# lt3-image-spam.sh -- multiplying image popups (feh preferred, eog/mirage
# fallback). Every window is dismissible; lundo closes the rest.
set -u
COUNT=6
GAP=4
IMG="${1:-/tmp/ccdc-taunt.png}"
LEDGER="$(dirname "$0")/../taunt-ledger.jsonl"
DISPLAY="${DISPLAY:-:0}"; export DISPLAY

VIEWER=""
for c in feh eog mirage; do command -v "$c" >/dev/null && VIEWER="$c" && break; done
[ -z "$VIEWER" ] && { echo "no image viewer found (feh/eog/mirage)"; exit 1; }
[ -f "$IMG" ] || { echo "image missing: $IMG (run lt1 first or pass a path)"; exit 1; }

for i in $(seq 1 "$COUNT"); do
    if [ "$VIEWER" = feh ]; then
        feh --fullscreen --geometry 640x480+$((RANDOM%600))+$((RANDOM%400)) "$IMG" >/dev/null 2>&1 &
    else
        "$VIEWER" "$IMG" >/dev/null 2>&1 &
    fi
    printf '{"ts":"%s","playbook":"ccdc-taunt","step":"image-popup","index":%d}\n' \
        "$(date +%s)" "$i" >> "$LEDGER"
    echo "== popup $i/$COUNT"
    [ "$i" -lt "$COUNT" ] && sleep "$GAP"
done
echo "== done. undo: sudo ./lundo.sh"
