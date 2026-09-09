"""YARA-style static signature pack + file scanner (pure-stdlib substring/regex rules).

Each rule is evaluated over the first N bytes of a file. Rules mirror the
research docs: Realm imix config strings, Rust-implant heuristics, static-musl
ELF builds, Eldritch tomes, and webshell content patterns.
"""
import re, os, hashlib, time
from . import state

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"

RULES = [
    dict(id="SIG-REALM-IMIX", name="Realm imix implant (config strings)", severity="critical",
         strings=[b"IMIX_CALLBACK_URI", b"IMIX_SERVER_PUBKEY", b"IMIX_BEACON_ID",
                  b"IMIX_GUARDRAILS", b"IMIX_CONFIG", b"main.eldritch", b"eldritch", b"tavern"],
         require=4, magic=PE_MAGIC + ELF_MAGIC,
         why="Binary carries the documented imix compile-time config surface (IMIX_* env "
             "names / eldrift / tavern strings). See development-research/realm-implant-test-payload-guide.md"),
    dict(id="SIG-RUST-IMPLANT", name="Unsigned Rust binary with C2-ish traits", severity="high",
         strings=[b"rust_begin_unwind", b"panicked at ", b"/rustc/", b"TcpStream", b"chacha"],
         require=3, magic=PE_MAGIC + ELF_MAGIC,
         why="Rust-compiled executable combining runtime markers with network/crypto symbols. "
             "Population of unsigned Rust binaries on a CCDC gold image is ~zero."),
    dict(id="SIG-MUSL-ELF", name="Static musl ELF build", severity="medium",
         strings=[b"musl", b"IMIX_", b"eldritch"], require=2, magic=ELF_MAGIC,
         why="Static musl-linked ELF carrying implant config strings - matches imix Linux builds."),
    dict(id="SIG-ELDRITCH-TOME", name="Eldritch tome script", severity="high",
         strings=[b"eldritch", b"load_library", b"reflective", b"reverse_shell", b"def "],
         require=2, magic=None,
         why="Script file matching Realm 'eldritch' tome content patterns."),
    dict(id="SIG-WEBSHELL-PHP", name="PHP webshell patterns", severity="critical",
         strings=[b"eval($_", b"assert($_", b"system($_", b"shell_exec(", b"passthru($_",
                  b"base64_decode($_", b'preg_replace("/./e"', b"$_REQUEST[", b"$_POST["],
         require=1, magic=None, exts=(".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx"),
         why="Classic webshell dispatch: user input straight into code-execution primitives."),
    dict(id="SIG-CS-BEACON", name="Cobalt Strike beacon indicators", severity="critical",
         strings=[b"%%IMPORT%%", b"ReflectiveLoader", b"beacon.dll", b"msagent_", b"postex_"],
         require=2, magic=PE_MAGIC,
         why="Static indicators of Cobalt Strike beacon/stager builds."),
    dict(id="SIG-HAVOC-DEMON", name="Havoc Demon indicators", severity="critical",
         strings=[b"Demon", b"Havoc", b"HellsGate", b"SleepObf", b"demon.x64.dll", b"\\\\Havoc\\"],
         require=2, magic=PE_MAGIC,
         why="Static indicators of the Havoc Demon agent or its loaders."),
    dict(id="SIG-MINGW", name="MinGW/GCC-compiled binary", severity="high",
         strings=[b"GCC: (GNU)", b"libgcc", b"libstdc++", b"mingw32", b"__gxx_personality_v0",
                  b"mingw-w64", b"cygwin", b"ZpIkLmG]", b"_gnu_exception_handler"],
         require=2, magic=PE_MAGIC,
         why="Binary compiled with MinGW/g++ on a production Windows server. watershell-cpp "
             "ships as a g++ build, and corporate enterprise software is MSVC-signed - "
             "libgcc/libstdc++ runtime imports here are a strong implant indicator."),
    dict(id="SIG-AMSI-BYPASS", name="AMSI bypass / tamper pattern", severity="critical",
         strings=[b"amsiInitFailed", b"AmsiScanBuffer", b"AmsiInitialize", b"amsi.dll",
                  b"System.Management.Automation.AmsiUtils", b"NonPublic,Static",
                  b"SET_CONTENT", b"REF].Assembly"],
         require=2, magic=None,
         why="AMSI bypass tradecraft: forcing amsiInitFailed, patching AmsiScanBuffer, "
             "or reflecting over AmsiUtils to disable script scanning."),
    dict(id="SIG-WATERSHELL", name="Watershell raw-packet shell (RITRedteam)", severity="critical",
         strings=[b"status:", b"run:", b"/proc/net/arp", b"/proc/net/route",
                  b"Running in promisc mode", b"TCP mode (experimental)", b"00000000"],
         require=3, magic=ELF_MAGIC,
         why="Watershell (watershell-cpp) receives commands as raw Ethernet/IP frames on a "
             "BPF-filtered PF_PACKET socket (no listening port) and matches packet payloads "
             "against the 'status:'/'run:' magic prefixes while parsing /proc/net/arp and "
             "/proc/net/route to hand-craft L2 replies. These traits are its binary fingerprint."),
    dict(id="SIG-DOTNET-OFFTOOL", name="Offensive .NET tool assembly name", severity="critical",
         strings=[b"Rubeus", b"Seatbelt", b"SharpHound", b"SharpSploit", b"winPEAS",
                  b"Covenant.Launcher", b"GhostPack", b"SharpDPAPI", b"SharpRoast", b"SharpWMI"],
         require=1, magic=None,
         why="Assembly/file name matches known offensive .NET post-exploitation tooling "
             "(file-less loads carry these names into .NET Loader ETW events)."),
]

USER_WRITABLE_DIRS = [
    os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
    os.path.join(os.environ.get("APPDATA", ""), ""), os.environ.get("PUBLIC", ""),
    os.path.join(os.environ.get("PROGRAMDATA", ""), ""),
    "C:\\Windows\\Temp", "C:\\inetpub\\wwwroot", "C:\\var\\www", "C:\\www",
]
SCAN_EXTS = (".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".psm1", ".vbs", ".js", ".hta",
             ".bat", ".cmd", ".php", ".phtml", ".jsp", ".asp", ".aspx", ".eldritch", ".py", ".pl",
             ".elf", ".bin", ".so", ".out")
MAX_READ = 8 * 1024 * 1024

_scanned = {}   # path -> (size, mtime, verdict)

def scan_bytes(data, memory=False):
    """Match signature rules. memory=True skips the PE/ELF magic requirement -
    memory chunks never begin with a file header."""
    hits = []
    for r in RULES:
        if r["magic"] and not memory:
            if not (data.startswith(PE_MAGIC) and PE_MAGIC in r["magic"]) and \
               not (data.startswith(ELF_MAGIC) and ELF_MAGIC in r["magic"]):
                continue
        n = sum(1 for s in r["strings"] if s in data)
        if n >= r["require"]:
            hits.append(r)
    return hits

def scan_file(path):
    """Scan one file if changed since last scan. Returns list of matched rule dicts."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    key = (st.st_size, int(st.st_mtime))
    if _scanned.get(path) == (key, True):
        return []                       # unchanged, previously clean
    # timestomp: file claims an mtime far older than its (unfakeable) creation time
    if hasattr(st, "st_ctime") and st.st_ctime - st.st_mtime > 60 * 60 * 24 * 30:
        from . import state as _state
        rec = _state.norm_event("filescan", "file", "high",
                                "Timestomped file: " + os.path.basename(path),
                                {"path": path, "mtime": int(st.st_mtime), "ctime": int(st.st_ctime)})
        _state.raise_alert("TIME-STOMP", "high", "Timestomped file: " + path,
                           "File's modification timestamp predates its creation by over 30 days. "
                           "NTFS creation time cannot be set by normal APIs, so backdating mtime "
                           "(the timestomp evasion) always leaves this signature.",
                           event=rec, data={"path": path, "mtime": int(st.st_mtime),
                                            "ctime": int(st.st_ctime)})
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except OSError:
        return []
    hits = scan_bytes(data)
    sha = hashlib.sha256(data).hexdigest()[:16]
    if hits:
        _scanned[path] = (key, False)
        rec = state.norm_event("filescan", "file", hits[0]["severity"],
                               "Signature hit: " + os.path.basename(path),
                               {"path": path, "sha256_16": sha, "size": st.st_size,
                                "sigs": [h["id"] for h in hits],
                                "content_sig": ("eldritch" if any(h["id"] == "SIG-ELDRITCH-TOME" for h in hits)
                                                else "webshell" if any(h["id"].startswith("SIG-WEBSHELL") for h in hits)
                                                else "")})
        from . import rules as rules_mod
        for h in hits:
            state.raise_alert(h["id"], h["severity"], h["name"], h["why"], event=rec,
                              data={"path": path, "sha256_16": sha})
        state.stats["signatures_hit"] += 1
        with state.LOCK:
            state.scans.append({"ts": time.time(), "path": path, "verdict": "malicious",
                                "sigs": [h["id"] for h in hits], "sha256_16": sha})
        return hits
    else:
        _scanned[path] = (key, True)
        with state.LOCK:
            state.scans.append({"ts": time.time(), "path": path, "verdict": "clean", "sha256_16": sha})
        return []

def scan_dirs(dirs=None, deep=6):
    """Walk common drop directories; scan new/changed files."""
    n = 0
    for d in (dirs or USER_WRITABLE_DIRS):
        if not d or not os.path.isdir(d):
            continue
        for root, dirnames, filenames in os.walk(d):
            if root.count(os.sep) - d.count(os.sep) >= deep:
                dirnames[:] = []
            dirnames[:] = [x for x in dirnames if x not in ("node_modules", ".git", "__pycache__")]
            for fn in filenames:
                if fn.lower().endswith(SCAN_EXTS):
                    scan_file(os.path.join(root, fn))
                    n += 1
                    state.stats["files_scanned"] += 1
    return n

def scan_process_image(path):
    """Scan a running process's image file (used by the process sensor)."""
    if path and os.path.isfile(path):
        return scan_file(path)
    return []
