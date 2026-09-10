#!/bin/bash
# lt2-browser-storm.sh -- staggered default-browser tabs (rickroll default).
set -u
TABS=5
GAP=7
URL="https://www.youtube.com/watch?v=dQw4w9WgXcQ"
LEDGER="$(dirname "$0")/../taunt-ledger.jsonl"
DISPLAY="${DISPLAY:-:0}"; export DISPLAY

command -v xdg-open >/dev/null || { echo "no xdg-open"; exit 1; }
for i in $(seq 1 "$TABS"); do
    xdg-open "$URL" >/dev/null 2>&1 &
    printf '{"ts":"%s","playbook":"ccdc-taunt","step":"tab-open","url":"%s"}\n' \
        "$(date +%s)" "$URL" >> "$LEDGER"
    echo "== tab $i/$TABS"
    [ "$i" -lt "$TABS" ] && sleep "$GAP"
done
echo "== done. undo closes spawned browser windows: sudo ./lundo.sh"
