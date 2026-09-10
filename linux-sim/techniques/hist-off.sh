# technique: history/accounting sabotage drop-in (guide 5.5)
name="hist-off"
plant() {
    echo 'export HISTFILE=/dev/null HISTSIZE=0 HISTCONTROL=ignoreboth # ccdc-sim' \
        > /etc/profile.d/00-ccdc-sim-histoff.sh
    : > /root/.bash_history 2>/dev/null || true
}
clean() {
    rm -f /etc/profile.d/00-ccdc-sim-histoff.sh
}
