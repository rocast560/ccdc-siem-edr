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
    inv = {"run": {}, "ifeo": {}, "appinit": {}, "services": {}, "tasks": [], "startup": [], "wmi": []}
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
    # WMI event subscriptions
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance -Namespace root\\subscription __EventFilter,"
                              "__CommandLineEventConsumer,__FilterToConsumerBinding -ErrorAction SilentlyContinue "
                              "| Select-Object __CLASS,Name | ConvertTo-Json -Compress"],
                             capture_output=True, text=True, errors="replace", timeout=60).stdout
        arr = json.loads(out) if out.strip() else []
        if isinstance(arr, dict): arr = [arr]
        for o in arr:
            inv["wmi"].append(o.get("__CLASS", "?") + ":" + o.get("Name", "?"))
    except Exception:
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
    return findings

def audit_cycle():
    """Diff current inventory against baseline; emit events + alerts for new artifacts."""
    if not os.path.isfile(BASELINE_FILE):
        take_baseline()
        return []
    with open(BASELINE_FILE) as f:
        base = json.load(f)
    cur = collect()
    findings = _diff(base, cur)
    for kind, rule_id, sev, title, path in findings:
        rec = state.norm_event("auditor", kind, sev, title, {"path": path})
        state.raise_alert(rule_id, sev, title,
                          "Persistence auditor diff against T0 baseline - artifact appeared after baseline capture.",
                          event=rec, data={"path": path})
        state.stats["persistence_diffs"] += 1
    return findings
