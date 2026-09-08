import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from edr import state, rules

rec = state.norm_event("eventlog", "eventlog", "info",
                       "Process creation (4688): MpCmdRun",
                       {"eid": "4688", "channel": "Security", "cmdline": "",
                        "path": r"C:\Users\Public\DefCheck\MpCmdRun.exe", "pid": "123"})
hits = rules.evaluate(rec)
print("rule hits:", hits)
print("alerts:", [(a["rule"], a["event"]["data"].get("path")) for a in state.alerts])
