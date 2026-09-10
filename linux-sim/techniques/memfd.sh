# technique: memfd_create fileless execution (guide 4.1) — runs /bin/sleep
# out of an anonymous memory fd; /proc/<pid>/exe shows memfd:ccdc-sim (deleted)
name="memfd"
plant() {
    command -v python3 >/dev/null || { echo "python3 missing - skipping"; return 1; }
    nohup python3 -c '
import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
fd = libc.memfd_create(b"ccdc-sim", 0)
payload = open("/bin/sleep", "rb").read()
os.write(fd, payload)
path = "/proc/self/fd/%d" % fd
os.execv(path, [path, "3600"])
' >/dev/null 2>&1 &
    echo $! > /run/ccdc-sim-memfd.pid
}
clean() {
    [ -f /run/ccdc-sim-memfd.pid ] && kill "$(cat /run/ccdc-sim-memfd.pid)" 2>/dev/null
    rm -f /run/ccdc-sim-memfd.pid
    for p in /proc/[0-9]*; do
        ls -l "$p/exe" 2>/dev/null | grep -q 'memfd:ccdc-sim' && kill "${p#/proc/}" 2>/dev/null
    done
}
