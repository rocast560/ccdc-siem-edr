# technique: firewall sabotage (guide 5.4) — state is saved first and
# restored by cleanup.sh; the DETECTION exercise is noticing it happened
name="firewall-off"
STATE="/run/ccdc-sim-iptables.state"
plant() {
    iptables-save > "$STATE" 2>/dev/null
    command -v ufw >/dev/null && ufw status | grep -q active && { ufw disable; echo ufw-was-active > /run/ccdc-sim-ufw.flag; }
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
}
clean() {
    if [ -s "$STATE" ]; then iptables-restore < "$STATE"; fi
    [ -f /run/ccdc-sim-ufw.flag ] && ufw enable && rm -f /run/ccdc-sim-ufw.flag
    rm -f "$STATE"
}
