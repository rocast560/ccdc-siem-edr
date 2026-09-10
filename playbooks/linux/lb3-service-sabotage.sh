#!/bin/bash
# lb3-service-sabotage.sh -- INTERVAL SERVICE-SABOTAGE playbook (Linux)
# Creates a DUMMY systemd service, then a jittered timer that stops and
# restarts it for N rounds, then removes itself. Guardrails: refuses a
# critical-services blocklist; only ever touches the dummy it created.
#   1. dummy service ccdc-simsvc (sleep loop)
#   2. sabotage timer (jittered stop -> restore -> repeat -> self-delete)
set -u
MARKER="ccdc-pb3"
DIR="$(cd "$(dirname "$0")" && pwd)"
LEDGER="$DIR/../ledger.jsonl"
SVC="ccdc-simsvc"
INTERVAL=300        # seconds between sabotages
RESTORE=120         # seconds before restart
ROUNDS=8

CRITICAL="ssh sshd systemd-journald systemd-logind dbus cron auditd rsyslog NetworkManager nginx apache2 docker"
for c in $CRITICAL; do [ "$SVC" = "$c" ] && { echo "refusing critical service"; exit 1; }; done
ledger() { printf '{"ts":"%s","playbook":"%s","step":"%s","artifact":"%s"}\n' \
    "$(date +%s)" "$MARKER" "$1" "$2" >> "$LEDGER"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

# ---- STEP 1: dummy service -------------------------------------------------
cat > /etc/systemd/system/$SVC.service <<EOF
[Unit]
Description=Locale cache maintenance (CCDC sim dummy)
[Service]
Type=simple
ExecStart=/bin/sh -c 'while :; do sleep 60; done'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now $SVC >/dev/null 2>&1
ledger "dummy-service" "/etc/systemd/system/$SVC.service"

# ---- STEP 2: self-limiting sabotage loop ------------------------------------
LOOP=/usr/local/sbin/.lc-maint
cat > $LOOP <<EOF
#!/bin/sh
# ccdc-pb3 sabotage loop: jittered stop/restore storm, then self-delete
for r in \$(seq 1 $ROUNDS); do
    sleep $((INTERVAL + RANDOM % 90))
    systemctl stop $SVC
    printf '{"ts":"%s","playbook":"$MARKER","step":"svc-stop","artifact":"$SVC"}\n' "\$(date +%s)" >> $LEDGER
    sleep $RESTORE
    systemctl start $SVC
done
systemctl disable --now ccdc-pb3.timer 2>/dev/null
rm -f '$LOOP' /etc/systemd/system/ccdc-pb3.timer
systemctl daemon-reload
EOF
chmod 700 $LOOP
ledger "sabotage-loop" "$LOOP"

cat > /etc/systemd/system/ccdc-pb3.timer <<EOF
[Unit]
Description=Locale maintenance window
[Timer]
OnBootSec=45s
Unit=ccdc-pb3.service
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/ccdc-pb3.service <<EOF
[Unit]
Description=Locale maintenance runner
[Service]
Type=oneshot
ExecStart=$LOOP
EOF
systemctl daemon-reload && systemctl enable --now ccdc-pb3.timer >/dev/null 2>&1
ledger "sabotage-timer" "/etc/systemd/system/ccdc-pb3.timer"

echo "== lb3 armed: $SVC stops every ~$((INTERVAL/60)) min for $ROUNDS rounds, restores after $((RESTORE/60)) min"
echo "   detection targets: auditd systemd key writes, the stop/start storm in journalctl"
echo "cleanup: sudo ./lcleanup.sh"
