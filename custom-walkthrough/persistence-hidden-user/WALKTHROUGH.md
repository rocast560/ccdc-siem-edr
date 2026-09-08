# Test: Persistence — hidden local account

**Chain:** a local account whose name ends in `$` disappears from `net user` output while
remaining fully usable for remote auth — the classic CCDC "mystery re-entry." Even more
advanced: inserting the account directly into the SAM registry bypasses the 4720 creation
event entirely (requires SYSTEM + SAM write; simulated here with the normal route to keep
the test safe).

**Implant setup:** not required (the account IS the persistence; pair it with any
delivery walkthrough later by adding it to Administrators).

**Victim (elevated PowerShell):** `.\test.ps1`

```powershell
net user cdcbackup$ Passw0rd! /add
net localgroup administrators cdcbackup$ /add
net user                              # the $-name does NOT appear here:
Get-LocalUser | Select Name           # ...but PowerShell's LocalUser module DOES show it
```

**Expected vs gap:**

| Event | Today |
|---|---|
| Account created via `net user /add` | ✅ `EVT-4720` (high) — Security channel account-creation event, already consumed |
| Added to Administrators | ✅ `EVT-4732` — also in the consumed set |
| `net user` visibility | ❌ hidden — exactly why the event log, not enumeration, must catch it |
| Registry-direct SAM insertion | ❌ GAP — no 4720 fires; needs a periodic local-account-vs-baseline audit (file it) |

**Fix to file:** an auditor category enumerating local users (`Get-LocalUser` /
`Win32_UserAccount`) and diffing against baseline — catches `$`-names AND
registry-inserted accounts regardless of how they appeared.

**Cleanup:** `net user cdcbackup$ /delete`.
