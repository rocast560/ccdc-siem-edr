# technique: run-then-delete binary (guide 4.2) — /proc/<pid>/exe shows (deleted)
name="deleted-binary"
plant() {
    cp /bin/sleep /tmp/.ccdc-sim-hidden
    /tmp/.ccdc-sim-hidden 3600 &
    echo $! > /run/ccdc-sim-deleted.pid
    rm -f /tmp/.ccdc-sim-hidden
}
clean() {
    [ -f /run/ccdc-sim-deleted.pid ] && kill "$(cat /run/ccdc-sim-deleted.pid)" 2>/dev/null
    rm -f /run/ccdc-sim-deleted.pid /tmp/.ccdc-sim-hidden
}
