# technique: systemd service + timer persistence (guide 2.2)
name="systemd-timer"
plant() {
    cat > /etc/systemd/system/ccdc-sim.service <<'UNIT'
[Unit]
Description=CCDC sim payload
[Service]
Type=simple
ExecStart=/usr/local/bin/ccdc-sim-beacon
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
    cat > /etc/systemd/system/ccdc-sim.timer <<'UNIT'
[Unit]
Description=CCDC sim timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now ccdc-sim.timer >/dev/null 2>&1
}
clean() {
    systemctl disable --now ccdc-sim.timer ccdc-sim.service >/dev/null 2>&1
    systemctl stop ccdc-sim.service >/dev/null 2>&1
    rm -f /etc/systemd/system/ccdc-sim.service /etc/systemd/system/ccdc-sim.timer
    systemctl daemon-reload
}
