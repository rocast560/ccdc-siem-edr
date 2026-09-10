#!/bin/bash
# lcleanup.sh -- removes every artifact planted by the Linux playbooks.
# Ground truth comes from ../ledger.jsonl plus the fixed locations.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
LEDGER="$DIR/../ledger.jsonl"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
echo "== lcleanup"

# processes: sleep-crypt loaders + unlinked binaries + sabotage loops
pkill -f 'X11-lock|x-shm|lc-maint|\.locale' 2>/dev/null && echo "   killed implant processes"
[ -f /run/ccdc-pb1-unlinked.pid ] && { kill "$(cat /run/ccdc-pb1-unlinked.pid)" 2>/dev/null; rm -f /run/ccdc-pb1-unlinked.pid; }
[ -f /run/ccdc-pb2.pid ] && { kill "$(cat /run/ccdc-pb2.pid)" 2>/dev/null; rm -f /run/ccdc-pb2.pid; }

# sabotage machinery + dummy service
systemctl disable --now ccdc-pb3.timer ccdc-simsvc 2>/dev/null
systemctl stop ccdc-pb3.timer ccdc-simsvc 2>/dev/null
rm -f /etc/systemd/system/ccdc-pb3.timer /etc/systemd/system/ccdc-pb3.service \
      /etc/systemd/system/ccdc-simsvc.service /usr/local/sbin/.lc-maint
systemctl daemon-reload

# ledger-driven removal (files + user-scope units)
if [ -f "$LEDGER" ]; then
    while IFS= read -r line; do
        artifact="$(printf '%s' "$line" | sed -n 's/.*"artifact":"\([^"]*\)".*/\1/p')"
        playbook="$(printf '%s' "$line" | sed -n 's/.*"playbook":"\([^"]*\)".*/\1/p')"
        case "$playbook" in ccdc-pb*) ;; *) continue ;; esac
        case "$artifact" in
            /dev/shm/*|/usr/local/*|/etc/.python_history) rm -f "$artifact" && echo "   removed $artifact" ;;
            */.config/systemd/user/*) rm -f "$artifact" "$artifact" ;;
            /home/*/.bashrc) sed -i '/ccdc-pb/d' "$artifact" 2>/dev/null ;;
            crontab:*) ct="${artifact#crontab:}"; ( crontab -u "$ct" -l 2>/dev/null | grep -v 'ccdc-pb' ) | crontab -u "$ct" - 2>/dev/null && echo "   cleaned crontab:$ct" ;;
        esac
    done < "$LEDGER"
fi
( crontab -l 2>/dev/null | grep -v 'ccdc-pb' ) | crontab - 2>/dev/null
rm -rf /usr/local/share/.cache
echo "== done; run sudo ./lverify.sh"
