#!/bin/bash
# linux-sim cleanup — removes every planted artifact and kills sim processes.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

echo "== linux-sim cleanup"

# stop payload loops first so removed files release
pkill -f 'ccdc-sim-beacon' 2>/dev/null && echo "   killed beacon loops"
systemctl stop ccdc-sim.service ccdc-sim.timer 2>/dev/null

for f in "$DIR"/techniques/*.sh; do
    name="$(basename "$f" .sh)"
    # shellcheck disable=SC1090
    ( . "$f"; clean >/dev/null 2>&1 ) && echo "   cleaned: $name"
done

# artifacts no technique owns
rm -f /usr/local/bin/ccdc-sim-beacon
rm -rf /root/ccdc-sim* /tmp/.ccdc-sim* /tmp/ccdc-sim* /run/ccdc-sim-*
userdel -f ccdc-sim 2>/dev/null
sed -i '/ccdc-sim/d' /root/.bashrc /root/.ssh/authorized_keys 2>/dev/null

echo "== cleanup done; run ./verify.sh to prove it"
