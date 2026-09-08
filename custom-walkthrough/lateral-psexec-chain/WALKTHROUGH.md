# Test: Lateral movement — the PsExec chain

**Chain:** PsExec-style remote execution leaves a distinctive artifact chain on the
**target**: `\\ADMIN$\system32` share write (5145) → `PSEXESVC.exe` dropped and installed
as a service (7045) → the service executing the payload. Testing it validates your
destination-side coverage of the most common CCDC lateral move.

**Two-machine:** run PsExec (Sysinternals) or `impacket psexec.py` from the attacker box
against this server's admin share. Single-box approximation (the artifact chain is
identical for the service half):

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md) optional.

**Victim (elevated PowerShell, simulating the destination half):**

```powershell
# what PsExec does on the target (simplified):
Copy-Item C:\Users\Public\sysupd.exe C:\Windows\System32\PSEXESVC.exe   # via ADMIN$ in the real attack
sc.exe create PSEXESVC binPath= "C:\Windows\System32\PSEXESVC.exe" displayname= "PSEXESVC"
sc.exe start PSEXESVC
```

**Expected vs gap:**

| Artifact | Today |
|---|---|
| Service install | ✅ `EVT-7045` (critical) + `PERS-SERVICE` — your strongest lateral signal |
| `PSEXESVC.exe` executing from System32 | ⚠️ process telemetry only — no rule keys on the name (System32 path defeats path rules; correct behavior — but a name-based `PROC-PSEXESVC` rule is worth adding since the name is the tell) |
| ADMIN$ share write (5145) | ❌ GAP — 5145/5140 not consumed; needs the channel + filter for `\\*\ADMIN$`/`\\*\IPC$` |

**Fix to file:** (a) add 5145 to the eventlog channels filtered to ADMIN$/IPC$ paths;
(b) a `PROC-PSEXESVC` rule (name PSEXESVC.exe → high; rename-resistant via the 7045 half).

**Cleanup:** `sc.exe delete PSEXESVC`; `Remove-Item C:\Windows\System32\PSEXESVC.exe`.
