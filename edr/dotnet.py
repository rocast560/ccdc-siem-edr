"""File-less .NET detection: consume the DotNETRuntime ETW provider.

Starts an ETW session for Microsoft-Windows-DotNETRuntime (Loader keyword,
0x8) and periodically converts the .etl with tracerpt. Assembly-load events
carrying offensive tool names (Rubeus, Seatbelt, SharpHound, ...) are alerted
via the SIG-DOTNET-OFFTOOL signature pack. This is the layer that sees
Assembly.Load-from-bytes, which never touches the file scanner.
"""
import os, re, subprocess, glob
from . import state, rules, signatures

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state")
SESSION = "CCDCEdrDotNet"
ETL = os.path.join(STATE, "dotnet.etl")
XML = os.path.join(STATE, "dotnet.xml")

_seen = set()

def start():
    os.makedirs(STATE, exist_ok=True)
    subprocess.run(["logman", "stop", SESSION, "-ets"], capture_output=True, timeout=30)
    r = subprocess.run(["logman", "start", SESSION, "-ets", "-p",
                        "{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}", "0x8", "-o", ETL],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0

# tracerpt renders provider fields as bare elements (<AssemblyName>x</AssemblyName>);
# some builds use Data Name= form - accept both
ASSEMBLY_RX = re.compile(
    r"(?:<AssemblyName>|<Data Name=[\"']AssemblyName[\"']>)([^<]{1,300})<")

def poll():
    """Dump the session buffer and screen assembly names against the sig pack."""
    if not os.path.isfile(ETL):
        return
    # copy-then-convert: tracerpt needs the file unlocked; logman keeps writing,
    # so we stop/restart around the dump (sub-second gap).
    subprocess.run(["logman", "stop", SESSION, "-ets"], capture_output=True, timeout=30)
    try:
        subprocess.run(["tracerpt", ETL, "-o", XML, "-of", "XML", "-y"],
                       capture_output=True, timeout=120)
    finally:
        subprocess.run(["logman", "start", SESSION, "-ets", "-p",
                        "{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}", "0x8", "-o", ETL],
                       capture_output=True, timeout=60)
    try:
        with open(XML, "r", errors="replace") as f:
            data = f.read()
    except OSError:
        return
    for name in set(ASSEMBLY_RX.findall(data)):
        if name in _seen:
            continue
        _seen.add(name)
        hits = signatures.scan_bytes(name.encode())
        sev = "info"
        rec = state.norm_event("dotnet", "file", sev, f".NET assembly load: {name[:120]}",
                               {"path": name[:200], "content_sig": ""})
        for h in hits:
            sev = h["severity"]
            state.raise_alert(h["id"], h["severity"],
                              f".NET {h['name']}: {name[:80]}",
                              h["why"] + " Observed via the .NET runtime Loader ETW provider, "
                              "which sees file-less Assembly.Load(byte[]) that never touches disk.",
                              event=rec, data={"assembly": name[:160]})
        rules.evaluate(rec)
    # keep the xml from growing unbounded
    for p in glob.glob(XML + "*") + glob.glob(ETL + "*"):
        if os.path.isfile(p) and p != ETL:
            try:
                os.remove(p)
            except OSError:
                pass
