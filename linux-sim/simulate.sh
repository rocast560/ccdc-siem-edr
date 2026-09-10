#!/bin/bash
# linux-sim — interval attack simulation for blue-team detection testing.
# Plants marked, benign persistence/evasion techniques and logs ground truth.
# Practice images only. Nothing here touches the network.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$DIR/actions.log"
BEACON="/usr/local/bin/ccdc-sim-beacon"
INTERVAL=300
COUNT=0
ONLY=""
ALL=0
NOCLEAN=0

log_action() { # technique action artifacts...
    local t="$1" a="$2"; shift 2
    printf '{"ts":"%s","iso":"%s","technique":"%s","action":"%s","artifacts":[%s]}\n' \
        "$(date +%s)" "$(date -u +%FT%TZ)" "$t" "$a" \
        "$(printf '"%s",' "$@" | sed 's/,$//')" >> "$LOG"
}

make_beacon() { # benign payload every technique references: a pure sleep loop
    if [ ! -x "$BEACON" ]; then
        printf '#!/bin/sh\n# ccdc-sim benign payload: sleeps forever, no network\nwhile :; do sleep 60; done\n' > "$BEACON"
        chmod 755 "$BEACON"
    fi
}

load_techniques() {
    TECHS=""
    for f in "$DIR"/techniques/*.sh; do
        # shellcheck disable=SC1090
        (. "$f") || true
    done
    TECHS="$(ls "$DIR"/techniques/*.sh | xargs -n1 basename | sed 's/\.sh$//' | tr '\n' ' ')"
}

run_technique() {
    local name="$1"
    local script="$DIR/techniques/$name.sh"
    [ -f "$script" ] || { echo "!! unknown technique: $name"; return 1; }
    echo "==> planting: $name"
    # shellcheck disable=SC1090
    if ( . "$script"; plant ); then
        log_action "$name" "plant" "$script"
        return 0
    fi
    echo "!! plant failed: $name"
    log_action "$name" "error" "$script"
    return 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)    ls "$DIR"/techniques/*.sh | xargs -n1 basename | sed 's/\.sh$//'; exit 0 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --count)   COUNT="$2"; shift 2 ;;
        --only)    ONLY="$2"; shift 2 ;;
        --all)     ALL=1; shift ;;
        --no-cleanup) NOCLEAN=1; shift ;;
        *) echo "usage: simulate.sh [--all | --interval N --count N | --only a,b] [--no-cleanup]"; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (system persistence needs it)"; exit 1; }
[ -d "$DIR/techniques" ] || { echo "techniques/ missing"; exit 1; }

load_techniques
make_beacon
echo "== linux-sim starting: ground truth -> $LOG"

cleanup_on_exit() {
    if [ "$NOCLEAN" -eq 0 ]; then
        echo "== auto-cleanup (use --no-cleanup to leave artifacts for hunting)"
        "$DIR/cleanup.sh" >/dev/null 2>&1
    fi
}
trap cleanup_on_exit EXIT INT TERM

if [ "$ALL" -eq 1 ]; then
    for t in $TECHS; do run_technique "$t"; sleep 2; done
    echo "== planted all; hunting window open. Ctrl-C to clean up."
    sleep infinity
fi

if [ -n "$ONLY" ]; then
    IFS=',' read -ra PICKED <<< "$ONLY"
    for t in "${PICKED[@]}"; do run_technique "$(echo "$t" | xargs)"; sleep 2; done
    echo "== done; Ctrl-C to clean up."
    sleep infinity
fi

# interval chaos mode: a random technique every INTERVAL seconds
i=0
while :; do
    if [ "$COUNT" -gt 0 ] && [ "$i" -ge "$COUNT" ]; then echo "== finished $COUNT rounds"; break; fi
    pool=($TECHS)
    pick="${pool[$((RANDOM % ${#pool[@]}))]}"
    run_technique "$pick"
    i=$((i+1))
    sleep "$INTERVAL"
done
