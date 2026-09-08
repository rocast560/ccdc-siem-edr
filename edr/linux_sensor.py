"""Linux-side sensor (activates automatically when the EDR runs on Linux).

Covers the watershell-cpp class of implant: raw PF_PACKET sockets that never
appear as listening ports in netstat/ss. /proc/net/packet lists every packet
socket with its inode; we map inodes to owning pids via /proc/*/fd and alert
on any non-system process holding one. Also scans running process cmdlines
for watershell invocations (-l port / -i iface flags).
"""
import os, re, glob
from . import state

RX_IFACE = re.compile(r"^\s*\d+:\s+(\S+)")

def _packet_socket_pids():
    """{pid: [iface,...]} for processes owning AF_PACKET sockets."""
    inodes = {}
    try:
        with open("/proc/net/packet") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    inodes[parts[-1]] = parts[6] if len(parts) > 6 else "?"
    except OSError:
        return {}
    owners = {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        m = re.match(r"socket:\[(\d+)\]", target)
        if m and m.group(1) in inodes:
            pid = int(fd.split("/")[2])
            owners.setdefault(pid, set()).add(inodes[m.group(1)])
    return owners

def _pid_cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        return ""

SYSTEM_PIDS = {1, 2}
_allowed = {"systemd-resolved", "dhclient", "NetworkManager", "wpa_supplicant",
            "tcpdump", "snort", "zeek", "suricata"}

def poll():
    if os.name != "posix":
        return []
    owners = _packet_socket_pids()
    hits = []
    for pid, ifaces in owners.items():
        if pid in SYSTEM_PIDS:
            continue
        cmd = _pid_cmdline(pid)
        base = cmd.split()[0] if cmd else ""
        if os.path.basename(base) in _allowed:
            continue
        rec = state.norm_event("linux", "process", "critical",
                               "Raw packet socket held by %s (pid %d)" % (base or "?", pid),
                               {"cmdline": cmd or "pid %d" % pid, "pid": pid})
        from . import rules
        rules.evaluate(rec)
        state.raise_alert("PKT-SOCKET", "critical",
                          "Raw AF_PACKET socket (watershell-class implant)",
                          "Process owns a PF_PACKET raw socket without being a known resolver/"
                          "capture tool. Watershell (RITRedteam watershell-cpp) receives commands "
                          "as raw Ethernet frames through such a socket with a BPF filter - it "
                          "has NO listening port, so netstat/ss show nothing. This enumeration "
                          "is the layer that catches it.",
                          event=rec, data={"pid": pid, "cmdline": cmd[:200]})
        hits.append((pid, cmd))
    return hits
