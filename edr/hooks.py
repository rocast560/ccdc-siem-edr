"""Advanced in-memory sensor: API-hook tampering + unbacked threads.

1. NTDLL-INTEGRITY - for candidate processes, read the mapped ntdll .text
   section and compare against the on-disk copy. Divergence means bytes were
   patched in memory: malware inline-hooking syscalls, or EDR unhooking
   (Havoc/CS post-exploitation both do it). Flag any non-zero diff count with
   the offsets.

2. THREAD-UNBACKED - walk each candidate's threads; a start address that
   lands in private RWX/committed memory (no module backing) is the artifact
   of thread-hollowing / classic CreateRemoteThread injection: legitimate
   threads start inside a mapped image.
"""
import ctypes, os, struct, subprocess, json
from ctypes import wintypes
from . import state, rules
from . import memscan as _memscan

k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenThread.restype = ctypes.c_void_p
k32.OpenThread.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ntdll.NtQueryInformationThread.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.c_void_p]

THREAD_QUERY_LIMITED = 0x1000
THREAD_QUERY_INFORMATION = 0x0040   # required for ThreadQuerySetWin32StartAddress
THREAD_GET_CONTEXT = 0x0008
THREAD_SUSPEND_RESUME = 0x0002

class CONTEXT64(ctypes.Structure):
    _fields_ = [("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
                ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
                ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
                ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
                ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
                ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
                ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
                ("EFlags", ctypes.c_uint32),
                ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64),
                ("Dr3", ctypes.c_uint64), ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
                ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64),
                ("Rbx", ctypes.c_uint64), ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
                ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
                ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64),
                ("R11", ctypes.c_uint64), ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
                ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64), ("Rip", ctypes.c_uint64),
                ("FltSave", ctypes.c_byte * 512), ("VectorRegister", ctypes.c_byte * 416),
                ("VectorControl", ctypes.c_uint64),
                ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64),
                ("LastBranchFromRip", ctypes.c_uint64), ("LastExceptionToRip", ctypes.c_uint64),
                ("LastExceptionFromRip", ctypes.c_uint64)]

def _in_private_exec(h, addr):
    """True if addr lies in private executable memory (no module backing)."""
    mbi = _memscan.MEMORY_BASIC_INFORMATION()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return False
    return mbi.Type == 0x20000 and (mbi.Protect & 0xF0)

def _aligned_context():
    """x64 CONTEXT must be 16-byte aligned (DECLSPEC_ALIGN(16)); over-allocate
    and hand back an aligned cast."""
    raw = ctypes.create_string_buffer(ctypes.sizeof(CONTEXT64) + 16)
    addr = (ctypes.addressof(raw) + 15) & ~15
    return ctypes.cast(addr, ctypes.POINTER(CONTEXT64))

PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400
TH32CS_SNAPTHREAD = 0x4

DISK_NTDLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntdll.dll")
_text_cache = None          # (va_offset, size, sha of chunks)
_checked = set()

class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long), ("dwFlags", wintypes.DWORD)]

def _disk_ntdll_text():
    """Parse on-disk ntdll: return (raw pointer to file bytes, text RVA, size)."""
    global _text_cache
    if _text_cache:
        return _text_cache
    try:
        data = open(DISK_NTDLL, "rb").read()
    except OSError:
        return None
    if data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_size
    for i in range(nsec):
        off = sec_off + i * 40
        name = data[off:off + 8].rstrip(b"\x00")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
        if name == b".text":
            _text_cache = (data, raddr, min(rsize, vsize))
            return _text_cache
    return None

def _find_mapped(h, modulename="ntdll.dll"):
    """Reserved for future per-module integrity checks."""
    return None

def check_ntdll(pid, name, path, h):
    cached = _disk_ntdll_text()
    if not cached:
        return
    data, raddr, tsize = cached
    if tsize > 0x400000:
        tsize = 0x400000
    # locate ntdll's mapped base: walk image regions and match the on-disk header
    mbi = _memscan.MEMORY_BASIC_INFORMATION()
    addr = 0
    base = None
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        b = mbi.BaseAddress or 0
        sz = mbi.RegionSize or 0
        if mbi.State == 0x1000 and mbi.Type == 0x1000000 and sz >= 0x1000:  # committed image map
            head = ctypes.create_string_buffer(0x100)
            got = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(b), head, 0x100, ctypes.byref(got)) \
                    and got.value == 0x100 and head.raw[:0x100] == data[:0x100]:
                base = b
                break
        addr = b + sz
    if base is None:
        return
    # compare .text in 64KB chunks; count differing chunks
    buf = ctypes.create_string_buffer(0x10000)
    got = ctypes.c_size_t(0)
    diffs = []
    for ofs in range(0, tsize, 0x10000):
        n = min(0x10000, tsize - ofs)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(base + raddr + ofs), buf, n, ctypes.byref(got)):
            continue
        if got.value == n and buf.raw[:n] != data[raddr + ofs:raddr + ofs + n]:
            diffs.append(hex(base + raddr + ofs))
        if len(diffs) >= 8:
            break
    if diffs:
        rec = state.norm_event("hooks", "process", "critical",
                               "ntdll .text patched in %s (pid %d): %d regions" % (name, pid, len(diffs)),
                               {"cmdline": path or name, "pid": pid,
                                "patched_regions": ",".join(diffs)})
        rules.evaluate(rec)
        state.raise_alert("NTDLL-TAMPER", "critical",
                          "API hooks / EDR unhooking in %s (pid %d)" % (name, pid),
                          "The ntdll .text section in this process differs from the on-disk "
                          "ntdll.dll - syscall stubs were patched in memory. Attackers inline-"
                          "hook APIs to redirect execution ( credential capture, control flow "
                          "theft) and post-exploitation frameworks patch ntdll to strip EDR "
                          "usermode hooks. Either way, memory no longer matches disk.",
                          event=rec, data={"pid": pid, "path": path, "regions": diffs})

def check_threads(pid, name, path, h):
    """Flag threads whose start address has no module backing (private RWX)."""
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap:
        return
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(THREADENTRY32)
    threads = []
    try:
        if k32.Thread32First(snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == pid:
                    threads.append(te.th32ThreadID)
                te.dwSize = ctypes.sizeof(THREADENTRY32)
                if not k32.Thread32Next(snap, ctypes.byref(te)):
                    break
    finally:
        k32.CloseHandle(snap)
    # module ranges for backing check
    from . import modules as _mods
    ranges = []
    for mod_name, mod_path in _mods._modules(pid):
        pass  # paths only; we use VirtualQuery on the start address instead
    flagged = 0
    hijacked = 0
    stack_hits = 0
    ctx_checked = 0
    for tid in threads[:60]:
        th = k32.OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, False, tid)
        if not th:
            continue
        try:
            start = ctypes.c_void_p()
            # NtQueryInformationThread(ThreadQuerySetWin32StartAddress = 9)
            if ntdll.NtQueryInformationThread(th, 9, ctypes.byref(start),
                                              ctypes.sizeof(start), None) == 0 and start.value:
                mbi = _memscan.MEMORY_BASIC_INFORMATION()
                if k32.VirtualQueryEx(h, start, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    prot = mbi.Protect
                    mtype = mbi.Type
                    if mtype == 0x20000 and (prot & 0xF0):   # MEM_PRIVATE + executable
                        flagged += 1
            # thread-context hijack: current RIP in private executable memory
            if ctx_checked < 12:
                ctx_checked += 1
                ctxp = _aligned_context()
                ctxp.contents.ContextFlags = 0x10000B         # CONTEXT_CONTROL (x64)
                if k32.GetThreadContext(th, ctxp) and ctxp.contents.Rip:
                    rip = ctxp.contents.Rip
                    rsp = ctxp.contents.Rsp
                    if _in_private_exec(h, rip):
                        hijacked += 1
                    # stack anomaly: return addresses on the stack pointing into
                    # unbacked memory (stack-spoofed / injected frames)
                    sbuf = ctypes.create_string_buffer(0x200)
                    got2 = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(rsp), sbuf, 0x200,
                                             ctypes.byref(got2)) and got2.value >= 8:
                        for off in range(0, got2.value - 7, 8):
                            val = struct.unpack_from("<Q", sbuf.raw, off)[0]
                            if 0x10000 < val < 0x7FFFFFFFFFFF and _in_private_exec(h, val):
                                stack_hits += 1
                                break
        finally:
            k32.CloseHandle(th)
    if flagged >= 1:
        rec = state.norm_event("hooks", "process", "critical",
                               "Threads starting in private memory: %s (pid %d)" % (name, pid),
                               {"cmdline": path or name, "pid": pid})
        rules.evaluate(rec)
        state.raise_alert("THREAD-UNBACKED", "critical",
                          "Injected thread(s) in %s (pid %d)" % (name, pid),
                          "This process has Win32 thread start addresses inside private "
                          "executable memory with no module backing - the artifact of classic "
                          "CreateRemoteThread/thread-hollowing injection. Legitimate threads "
                          "begin inside a mapped image.",
                          event=rec, data={"pid": pid, "path": path, "count": flagged})
    if hijacked >= 1:
        rec = state.norm_event("hooks", "process", "critical",
                               "Thread RIP in private memory: %s (pid %d)" % (name, pid),
                               {"cmdline": path or name, "pid": pid})
        rules.evaluate(rec)
        state.raise_alert("THREAD-HIJACK", "critical",
                          "Thread execution context hijacked in %s (pid %d)" % (name, pid),
                          "A live thread's instruction pointer sits in private executable memory "
                          "with no module backing - the aftermath of SetThreadContext redirection "
                          "(thread hijacking) used by process hollowing and sleeper injections.",
                          event=rec, data={"pid": pid, "path": path, "count": hijacked})
    if stack_hits >= 1:
        rec = state.norm_event("hooks", "process", "high",
                               "Stack return address in unbacked memory: %s (pid %d)" % (name, pid),
                               {"cmdline": path or name, "pid": pid})
        rules.evaluate(rec)
        state.raise_alert("STACK-UNBACKED", "high",
                          "Unbacked return address on thread stack in %s (pid %d)" % (name, pid),
                          "A return address on this thread's stack points into private executable "
                          "memory instead of a signed module - heap/stack anomaly typical of "
                          "injected call frames, stack spoofing, and indirect-syscall stubs "
                          "executing outside ntdll.",
                          event=rec, data={"pid": pid, "path": path})

_cycle = [0]           # round-robin cursor: long-running processes below the
                        # newest-first fold still get their turn eventually

def poll(limit=8):
    """Check non-system-noise processes (interpreters like python ARE
    candidates - they host injected code - unlike memscan's disk-drop focus)."""
    import os as _os
    from . import modules as _mods
    _self = {_os.getpid(), _os.getppid() if hasattr(_os, "getppid") else None}
    procs = [p for p in _mods._processes()
             if not (p[2] or "").lower().startswith(r"c:\windows")
             and p[0] not in _self]
    if not procs:
        return
    # rotate through the whole list instead of re-considering the newest pids
    # forever (a long-running implant would otherwise never be reached)
    start = _cycle[0] % len(procs)
    ordered = procs[start:] + procs[:start]
    _cycle[0] = start + limit
    done = 0
    for pid, name, path, _cdate in ordered:
        if pid in _checked or done >= limit:
            continue
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        done += 1
        _checked.add(pid)
        try:
            check_ntdll(pid, name, path, h)
            check_threads(pid, name, path, h)
        finally:
            k32.CloseHandle(h)
        if done >= limit:
            break
