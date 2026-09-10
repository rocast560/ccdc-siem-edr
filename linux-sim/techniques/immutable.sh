# technique: hostile immutable file (guide 5.2) — cleanup fails until noticed
name="immutable"
plant() {
    mkdir -p /usr/local/share
    echo 'ccdc-sim' > /etc/cron.blocked-ccdc-sim
    chattr +i /etc/cron.blocked-ccdc-sim 2>/dev/null || { rm -f /etc/cron.blocked-ccdc-sim; echo "chattr unavailable - skipping"; return 1; }
}
clean() {
    chattr -i /etc/cron.blocked-ccdc-sim 2>/dev/null
    rm -f /etc/cron.blocked-ccdc-sim
}
