"""Persistence auditor: enumerate every CCDC persistence location, baseline + diff.

Windows locations covered (see research guide section 2.3):
- HKCU/HKLM Run + RunOnce (+ Wow6432Node)
- Services (Win32_Service)
- Scheduled tasks (schtasks /query)
- Per-user + common Startup folders
- WMI event subscriptions (root subscription namespace)
- IFEO debugger hijacks, AppInit_DLLs
"""
import os, json, subprocess, time, winreg
from . import state, rules

BASELINE_PATH = os.path.join(os.path.dirname(__file__), "state")
BASELINE_FILE = os.path.join(BASELINE_PATH, "persistence-baseline.json")

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
APPINIT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
COM_HKCU = r"Software\Classes\CLSID"
LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
LSA_VALUES = ("Security Packages", "Notification Packages")
COR_ENV = ("COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH")
SIDECAND_PATHS = [r"C:\Program Files", r"C:\Program Files (x86)"]

# tranche-4 additions not covered above
SPE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
SSH_PATHS = [
    r"C:\ProgramData\ssh\authorized_keys",
    os.path.join(os.environ.get("USERPROFILE", ""), ".ssh\\authorized_keys"),
    r"C:\ProgramData\ssh\sshd_config",
]

def _enum_values(root, sub):
    out = {}
    for hive, name in ((root, sub), (root, sub)):
        try:
            k = winreg.OpenKey(hive, sub)
        except OSError:
            return out
        try:
            i = 0
            while True:
                try:
                    v, data, _ = winreg.EnumValue(k, i)
                    out[v] = str(data)
                except OSError:
                    break
                i += 1
        finally:
            winreg.CloseKey(k)
        break
    return out

def collect():
    """Full persistence inventory -> dict."""
    inv = {"run": {}, "ifeo": {}, "appinit": {}, "services": {}, "tasks": [], "startup": [], "wmi": [],
           "com": {}, "clr": {}, "lsa": {}, "task_actions": {}, "sideload": [],
           "screensaver": {}, "winlogon": {}, "psprofile": [], "bits": [], "uac": {},
           "netsh": {}, "appcert": {}, "timeprov": {}, "printmon": {},
           "activesetup": {}, "wlnotify": {}}
    for root, sub in RUN_KEYS:
        tag = ("HKCU\\" if root == winreg.HKEY_CURRENT_USER else "HKLM\\") + sub
        inv["run"][tag] = _enum_values(root, sub)
    # IFEO debuggers
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO)
        i = 0
        while True:
            try:
                img = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            d = _enum_values(winreg.HKEY_LOCAL_MACHINE, IFEO + "\\" + img)
            if "Debugger" in d:
                inv["ifeo"][img] = d["Debugger"]
        winreg.CloseKey(k)
    except OSError:
        pass
    # AppInit_DLLs
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, APPINIT)
        v, data = winreg.QueryValueEx(k, "AppInit_DLLs")
        data = str(data)
        if data.strip():
            inv["appinit"]["AppInit_DLLs"] = str(data)
        winreg.CloseKey(k)
    except OSError:
        pass
    # Services
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName "
                              "| ConvertTo-Json -Compress"],
                             capture_output=True, text=True, errors="replace", timeout=60).stdout
        arr = json.loads(out) if out.strip() else []
        if isinstance(arr, dict): arr = [arr]
        for s in arr:
            inv["services"][s["Name"]] = {"path": s.get("PathName") or "", "state": s.get("State"),
                                          "start": s.get("StartMode")}
    except Exception:
        pass
    # Scheduled tasks
    try:
        out = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/nh"], capture_output=True,
                             text=True, errors="replace", timeout=60).stdout
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if parts and parts[0]:
                inv["tasks"].append(parts[0])
    except Exception:
        pass
    # Startup folders
    dirs = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]
    for d in dirs:
        if os.path.isdir(d):
            for fn in os.listdir(d):
                inv["startup"].append(os.path.join(d, fn))
    # WMI event subscriptions (+ timers, with command lines for rule evaluation)
    # note: Get-CimInstance takes ONE class per call - query each separately.
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "'__EventFilter','__CommandLineEventConsumer',"
                              "'__FilterToConsumerBinding','__TimerInstruction' | "
                              "ForEach-Object { Get-CimInstance -Namespace root\\subscription "
                              "-ClassName $_ -ErrorAction SilentlyContinue } | "
                              "Select-Object __CLASS,Name,CommandLine,TimerId | ConvertTo-Json -Compress"],
                             capture_output=True, text=True, errors="replace", timeout=60).stdout
        arr = json.loads(out) if out.strip() else []
        if isinstance(arr, dict): arr = [arr]
        for o in arr:
            if not isinstance(o, dict):
                continue
            name = o.get("__CLASS") or o.get("CimClass", {}).get("CimClassName", "?")
            inv["wmi"].append(str(name) + ":" + str(o.get("Name") or o.get("TimerId") or "?"))
            cmd = o.get("CommandLine")
            if cmd:
                rec = state.norm_event("wmi", "process", "high",
                                       "WMI consumer command line: " + cmd[:120], {"cmdline": cmd})
                rules.evaluate(rec)
    except Exception:
        pass
    # COM hijack: HKCU CLSID shadows (InprocServer32 default value pointing outside system dirs)
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, COM_HKCU)
        i = 0
        while True:
            try:
                clsid = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            try:
                ik = winreg.OpenKey(k, clsid + r"\InprocServer32")
                v, data = winreg.QueryValueEx(ik, "")
                winreg.CloseKey(ik)
                d = str(data).lower()
                if d and not d.startswith(("c:\\windows\\", "c:\\program files")):
                    inv["com"][clsid] = str(data)
            except OSError:
                continue
        winreg.CloseKey(k)
    except OSError:
        pass
    # .NET CLR hijack: COR_* environment values (system + user) enabling a profiler
    for hive, tag in ((winreg.HKEY_LOCAL_MACHINE,
                       r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                      (winreg.HKEY_CURRENT_USER, "Environment")):
        vals = _enum_values(hive, tag)
        for name in COR_ENV:
            if name in vals and vals[name] not in ("0", ""):
                inv["clr"][tag.split("\\")[-1] + "\\" + name] = vals[name]
    # LSA security/notification packages
    lsa_vals = _enum_values(winreg.HKEY_LOCAL_MACHINE, LSA_KEY)
    for name in LSA_VALUES:
        cur = lsa_vals.get(name)
        if cur:
            base_pkgs = {"-", " SECURITY", "nosaSrv", "SCHANNEL", "WDIGEST", "kerberos",
                         "msv1_0", "tspkg", "pku2u", "cloudap", " ConsentRouter"}
            pkgs = [p.strip().lower() for p in cur.split(",")]
            extra = [p for p in pkgs if p and p not in {b.strip().lower() for b in base_pkgs}]
            if extra:
                inv["lsa"][name] = ",".join(extra)
    # Scheduled task ACTIONS (catch edits to existing tasks, not just new ones)
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-ScheduledTask | ForEach-Object { $a = ($_.Actions | "
                              "ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ';'; "
                              "\"$($_.TaskPath)$($_.TaskName)|$a\" }"],
                             capture_output=True, text=True, errors="replace", timeout=120).stdout
        import hashlib
        for line in out.splitlines():
            if "|" not in line:
                continue
            name, action = line.split("|", 1)
            inv["task_actions"][name.strip()] = hashlib.sha256(action.encode()).hexdigest()[:16]
    except Exception:
        pass
    # DLL side-load candidates: DLLs written into Program Files after baseline
    try:
        since = os.path.getmtime(BASELINE_FILE) if os.path.isfile(BASELINE_FILE) else 0
        import time as _t
        for root in SIDECAND_PATHS:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in ("WindowsApps",)]
                if root.count(os.sep) + 3 < dirpath.count(os.sep):
                    dirnames[:] = []
                for fn in filenames:
                    if fn.lower().endswith((".dll", ".ocx")):
                        p = os.path.join(dirpath, fn)
                        try:
                            if os.path.getmtime(p) > since + 1:
                                inv["sideload"].append(p)
                        except OSError:
                            pass
    except Exception:
        pass
    # Screensaver hijack (T1546.002): SCRNSAVE.EXE pointing anywhere unexpected
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop")
        v, data = winreg.QueryValueEx(k, "SCRNSAVE.EXE")
        inv["screensaver"]["SCRNSAVE.EXE"] = str(data)
        winreg.CloseKey(k)
    except OSError:
        pass
    # Winlogon Shell/Userinit hijack (T1547.004)
    for name in ("Shell", "Userinit"):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            v, data = winreg.QueryValueEx(k, name)
            inv["winlogon"][name] = str(data)
            winreg.CloseKey(k)
        except OSError:
            pass
    # PowerShell profile hijack (T1546.013): any of the four standard profile scripts
    pshome = os.path.join(os.environ.get("WINDIR", ""), r"System32\WindowsPowerShell\v1.0")
    userps = os.path.join(os.environ.get("USERPROFILE", ""), r"Documents\WindowsPowerShell")
    for prof in ("profile.ps1", "Microsoft.PowerShell_profile.ps1"):
        for base in (pshome, userps):
            p = os.path.join(base, prof)
            if os.path.isfile(p):
                inv["psprofile"].append(p)
    # BITS jobs (T1197): any queued BITS job is unusual on a server
    try:
        out = subprocess.run(["bitsadmin", "/list"],
                             capture_output=True, text=True, errors="replace", timeout=60).stdout
        for line in out.splitlines():
            if "{" in line and "GUID" not in line and line.strip():
                inv["bits"].append(line.strip()[:160])
    except Exception:
        pass
    # fodhelper-style UAC bypass key (T1548.002): ms-settings proxy in HKCU
    uac = _enum_values(winreg.HKEY_CURRENT_USER, r"Software\Classes\ms-settings\Shell\Open\command")
    for v in uac:
        inv["uac"][v] = uac[v]
    # netsh helper DLLs (T1546.007): values under HKLM\SOFTWARE\Microsoft\Netsh
    for v, dll in _enum_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Netsh").items():
        if dll:
            inv["netsh"][v] = str(dll)
    # AppCertDlls (T1546.009): loaded into every CreateProcess-calling process
    for v, dll in _enum_values(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls").items():
        if dll:
            inv["appcert"][v] = str(dll)
    # Time providers (T1547.012-ish): W32Time loads provider DLLs listed here
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders")
        i = 0
        while True:
            try:
                prov = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            d = _enum_values(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\\" + prov)
            dll = d.get("DllName", "")
            if dll and "w32time" not in dll.lower():
                inv["timeprov"][prov] = dll
        winreg.CloseKey(k)
    except OSError:
        pass
    # Print / port monitors (T1547.010): spooler loads monitor DLLs as SYSTEM
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Print\Monitors")
        i = 0
        while True:
            try:
                mon = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            d = _enum_values(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Print\Monitors\\" + mon)
            drv = d.get("Driver", "")
            if drv and drv.lower() not in ("localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll",
                                            "nthwprint.dll", "vpmntprint.dll"):
                inv["printmon"][mon] = drv
        winreg.CloseKey(k)
    except OSError:
        pass
    # Active Setup (T1547.014): StubPath executes at each user's first logon
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Active Setup\Installed Components")
        i = 0
        while True:
            try:
                comp = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            d = _enum_values(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Active Setup\Installed Components\\" + comp)
            if d.get("StubPath"):
                inv["activesetup"][comp] = d["StubPath"]
        winreg.CloseKey(k)
    except OSError:
        pass
    # Winlogon Notify (legacy but still honored): DLLs run at logon events
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify")
        i = 0
        while True:
            try:
                item = winreg.EnumKey(k, i); i += 1
            except OSError:
                break
            d = _enum_values(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\\" + item)
            if d.get("DLLName"):
                inv["wlnotify"][item] = d["DLLName"]
        winreg.CloseKey(k)
    except OSError:
        pass
    # SilentProcessExit MonitorProcess hijack (RoguePotato/Jenkins family)
    try:
        spe = _enum_values(winreg.HKEY_LOCAL_MACHINE, SPE_KEY)
        if spe.get("MonitorProcess"):
            inv.setdefault("spe", {})["MonitorProcess"] = spe["MonitorProcess"]
    except OSError:
        pass
    # SSH backdoors: authorized_keys contents hash + sshd_config directive changes
    import hashlib
    for p in SSH_PATHS:
        try:
            with open(p, "rb") as f:
                blob = f.read()
            if p.endswith("authorized_keys") and blob.strip():
                inv.setdefault("ssh", []).append(
                    p + ":" + hashlib.sha256(blob).hexdigest()[:16])
        except OSError:
            pass
    return inv

def take_baseline():
    os.makedirs(BASELINE_PATH, exist_ok=True)
    inv = collect()
    with open(BASELINE_FILE, "w") as f:
        json.dump(inv, f)
    state.norm_event("auditor", "audit", "info", "Persistence baseline captured",
                     {"run_keys": sum(len(v) for v in inv["run"].values()),
                      "services": len(inv["services"]), "tasks": len(inv["tasks"]),
                      "startup_items": len(inv["startup"]), "wmi_subs": len(inv["wmi"])})
    return inv

def _diff(base, cur):
    findings = []
    for key, vals in cur["run"].items():
        for v in vals:
            if v not in base.get("run", {}).get(key, {}):
                findings.append(("registry", "PERS-RUNKEY", "high",
                                 f"New autorun value: {key}\\{v} = {vals[v][:120]}", key + "\\" + v))
    for name, meta in cur["services"].items():
        if name not in base.get("services", {}):
            findings.append(("service", "PERS-SERVICE", "critical",
                             f"New service '{name}': {meta.get('path','')[:140]}", name))
    for t in cur["tasks"]:
        if t not in base.get("tasks", []):
            findings.append(("task", "PERS-TASK", "high", f"New scheduled task: {t}", t))
    for p in cur["startup"]:
        if p not in base.get("startup", []):
            findings.append(("file", "PERS-STARTUP", "high", f"New startup item: {p}", p))
    for w in cur["wmi"]:
        if w not in base.get("wmi", []):
            findings.append(("wmi", "PERS-WMI-SUB", "critical", f"New WMI subscription: {w}", w))
    for img, dbg in cur["ifeo"].items():
        if img not in base.get("ifeo", {}):
            findings.append(("registry", "PERS-IFEO", "critical",
                             f"IFEO debugger hijack on {img}: {dbg[:120]}", img))
    if cur["appinit"] and cur["appinit"] != base.get("appinit", {}):
        findings.append(("registry", "PERS-APPINIT", "critical", "AppInit_DLLs modified", "AppInit_DLLs"))
    for clsid, path in cur["com"].items():
        if clsid not in base.get("com", {}):
            findings.append(("registry", "PERS-COM", "critical",
                             f"COM hijack: HKCU CLSID {clsid} -> {path[:120]}", clsid))
    for name, val in cur["clr"].items():
        if name not in base.get("clr", {}):
            findings.append(("registry", "PERS-CLR", "critical",
                             f".NET CLR hijack: {name} = {val[:120]}", name))
    for name, extra in cur["lsa"].items():
        if (name, extra) not in [(k, v) for k, v in base.get("lsa", {}).items()]:
            findings.append(("registry", "PERS-LSA", "critical",
                             f"LSA package tamper: {name} non-standard entries: {extra[:120]}", name))
    for task, ahash in cur["task_actions"].items():
        if task in base.get("task_actions", {}) and base["task_actions"][task] != ahash \
                and task not in [f[4] for f in findings]:
            findings.append(("task", "PERS-TASKMOD", "high",
                             f"Scheduled task action modified: {task}", task))
    for p in cur["sideload"]:
        if p not in base.get("sideload", []):
            findings.append(("file", "PERS-SIDELOAD", "high",
                             f"DLL written into Program Files (side-load candidate): {p}", p))
    for v, target in cur["screensaver"].items():
        if base.get("screensaver", {}).get(v) != target:
            findings.append(("registry", "PERS-SCREENSAVER", "high",
                             f"Screensaver hijack: {v} = {target[:120]}", v))
    for name, val in cur["winlogon"].items():
        if base.get("winlogon", {}).get(name) != val:
            findings.append(("registry", "PERS-WINLOGON", "critical",
                             f"Winlogon {name} modified: {val[:120]}", name))
    for p in cur["psprofile"]:
        if p not in base.get("psprofile", []):
            findings.append(("file", "PERS-PSPROFILE", "high",
                             f"PowerShell profile appeared: {p}", p))
    for b in cur["bits"]:
        if b not in base.get("bits", []):
            findings.append(("job", "PERS-BITS", "high", f"New BITS job: {b[:120]}", b))
    for v, val in cur["uac"].items():
        if v not in base.get("uac", {}):
            findings.append(("registry", "PERS-UAC-KEY", "critical",
                             f"UAC bypass key (ms-settings proxy): {v} = {val[:120]}",
                             r"HKCU\Software\Classes\ms-settings"))
    for v, dll in cur["netsh"].items():
        if v not in base.get("netsh", {}):
            findings.append(("registry", "PERS-NETSH", "critical",
                             f"netsh helper DLL registered: {v} = {dll[:120]}", v))
    for v, dll in cur["appcert"].items():
        if v not in base.get("appcert", {}):
            findings.append(("registry", "PERS-APPCERT", "critical",
                             f"AppCertDlls entry (loads into every process): {v} = {dll[:120]}", v))
    for prov, dll in cur["timeprov"].items():
        if prov not in base.get("timeprov", {}):
            findings.append(("registry", "PERS-TIMEPROV", "critical",
                             f"Time provider DLL: {prov} = {dll[:120]}", prov))
    for mon, drv in cur["printmon"].items():
        if mon not in base.get("printmon", {}):
            findings.append(("registry", "PERS-PRINTMON", "critical",
                             f"Print/port monitor DLL: {mon} = {drv[:120]}", mon))
    for comp, stub in cur["activesetup"].items():
        if comp not in base.get("activesetup", {}):
            findings.append(("registry", "PERS-ACTIVESETUP", "critical",
                             f"Active Setup StubPath: {comp} = {stub[:120]}", comp))
    for item, dll in cur["wlnotify"].items():
        if item not in base.get("wlnotify", {}):
            findings.append(("registry", "PERS-WLNOTIFY", "critical",
                             f"Winlogon Notify DLL: {item} = {dll[:120]}", item))
    for name, val in cur.get("spe", {}).items():
        if name not in base.get("spe", {}):
            findings.append(("registry", "PERS-SPE", "critical",
                             f"SilentProcessExit {name}: {val[:120]}", SPE_KEY + "\\" + name))
    for ent in cur.get("ssh", []):
        if ent not in base.get("ssh", []):
            findings.append(("file", "PERS-SSH", "critical",
                             "SSH backdoor surface changed: " + ent.split(":")[0], ent))
    return findings

def check_exotic():
    """Presence-anomalous persistence that never shows in a baseline diff of
    standard locations (research: advanced-evasion-persistence-methods.md):

    1. PERS-UAC-PROBE  - HKCU ms-settings shell hijack keys. These only ever
       exist as part of fodhelper/computerdefaults-style auto-elevate bypass
       probes; near-zero FP.
    2. PERS-NTUSERMAN  - NTUSER.MAN profile hives. Writing persistence into
       the .MAN hive rides hive-load at logon and never fires
       registry-callback telemetry (Deceptiq research). The file should
       basically never exist on a normal system.
    """
    found = []
    # 1. UAC auto-elevate probe keys under HKCU
    for probe in (r"Software\Classes\ms-settings\Shell\Open\command",
                  r"Software\Classes\exefile\shell\open\command",
                  r"Software\Classes\Interface\{DB61FD6B-6DA6-4D76-8B3C-7AA7E1DF5CC5}"):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, probe)
            winreg.CloseKey(k)
            state.raise_alert("PERS-UAC-PROBE", "high",
                              "UAC auto-elevate probe key exists: " + probe,
                              "An HKCU class-registration key used by fodhelper/computerdefaults-style "
                              "UAC bypasses is present. Legitimate software does not create these under "
                              "a user hive - treat as an active elevation probe.",
                              data={"path": "HKCU\\" + probe})
            found.append(("registry", "PERS-UAC-PROBE", probe))
        except OSError:
            pass
    # 2. NTUSER.MAN hives in any profile ("Documents and Settings" is a
    # junction to Users on modern Windows - walking both double-reports)
    seen = set()
    for root in (os.environ.get("USERPROFILE", r"C:\Users") + r"\..",
                 r"C:\Users", r"C:\Users\Public"):
        root = os.path.realpath(root)
        if not root:
            continue
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for e in entries:
            man = os.path.join(root, e, "NTUSER.MAN")
            if os.path.realpath(man) in seen:
                continue
            try:
                st = os.stat(man)
            except OSError:
                continue
            seen.add(os.path.realpath(man))
            state.raise_alert("PERS-NTUSERMAN", "high",
                              "Profile mandatory hive present: " + man,
                              "NTUSER.MAN is a mandatory profile hive loaded at logon. Persistence "
                              "planted there rides hive-load and never triggers registry-callback "
                              "telemetry (it bypasses CmRegisterCallback-based sensors). Normal "
                              "systems do not carry this file outside domain-managed mandatory "
                              "profiles - verify provenance and hash immediately.",
                              data={"path": man, "size": st.st_size,
                                    "mtime": st.st_mtime})
            found.append(("file", "PERS-NTUSERMAN", man))
    return found

def audit_cycle():
    """Diff current inventory against baseline; emit events + alerts for new artifacts."""
    if not os.path.isfile(BASELINE_FILE):
        take_baseline()
        return []
    with open(BASELINE_FILE) as f:
        base = json.load(f)
    cur = collect()
    findings = _diff(base, cur)
    findings = findings + check_exotic()
    for kind, rule_id, sev, title, path in findings:
        rec = state.norm_event("auditor", kind, sev, title, {"path": path})
        # new service: scan its binary immediately (unsigned implant as svc)
        if rule_id == "PERS-SERVICE":
            meta = cur.get("services", {}).get(path) or {}
            binpath = (meta.get("path") or "").strip('"').split(" ")[0]
            if binpath and os.path.isfile(binpath):
                try:
                    from . import signatures as _sig
                    for h in _sig.scan_file(binpath):
                        state.raise_alert(h["id"], h["severity"],
                                          "Service binary signature: " + h["name"], h["why"],
                                          event=rec, data={"service": path, "binary": binpath})
                except Exception:
                    pass
        state.raise_alert(rule_id, sev, title,
                          "Persistence auditor diff against T0 baseline - artifact appeared after baseline capture.",
                          event=rec, data={"path": path})
        state.stats["persistence_diffs"] += 1
    return findings
