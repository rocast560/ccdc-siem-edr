# technique: SSH authorized_keys persistence (guide 1.2)
name="ssh-key"
plant() {
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIccccsimSIMsimSIMsimSIMsimSIMsim ccdc-sim@blue' >> /root/.ssh/authorized_keys
    echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIccccsim2SIM2sim2SIM2sim2SIM2sim2 ccdc-sim@blue' >> /root/.ssh/authorized_keys2
}
clean() {
    [ -f /root/.ssh/authorized_keys ] && sed -i '/ccdc-sim/d' /root/.ssh/authorized_keys
    rm -f /root/.ssh/authorized_keys2
}
