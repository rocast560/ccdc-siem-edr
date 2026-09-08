# Test: Privilege escalation — service misconfigurations

**Chain:** two classic local-privesc paths a CCDC red team hunts for: **unquoted service
paths** (a service whose binPath has spaces and no quotes lets a payload planted in an
earlier directory win the resolution) and **AlwaysInstallElevated** (MSI installs run as
SYSTEM).

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md) optional —
the enumeration half needs no implant; the hijack half stages one.

**Victim (elevated PowerShell):** `.\test.ps1`

**Part 1 — find + plant the unquoted-path hijack:**

```powershell
# enumerate vulnerable services (unquoted binPath with spaces, not in \Windows\):
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and
  ($_.PathName -split ' ')[0] -notmatch '\\Windows\\' } | Select Name, PathName

# simulate: create a service with an unquoted path through a writable parent
sc.exe create CCDCUnq binPath= C:\Users\Public\My Tools\svc.exe start= auto
# attacker then plants: C:\Users\Public\My.exe  (wins over "My Tools\svc.exe")
Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\My.exe
```

**Part 2 — AlwaysInstallElevated:**

```powershell
New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 1 -PropertyType DWord -Force
New-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 1 -PropertyType DWord -Force
# (attacker then ships any MSI - msiexec installs it as SYSTEM)
```

**Expected vs gap:**

| Event | Today |
|---|---|
| `sc create CCDCUnq` | ✅ `EVT-7045` + `PERS-SERVICE` — the service install itself fires |
| `My.exe` planted in Public | ✅ `SIG-*` on-write scan |
| Unquoted-path *condition* detected | ❌ GAP — no auditor check enumerates unquoted service paths |
| AlwaysInstallElevated keys set | ❌ GAP — no inventory of the Installer policy keys |

**Fix to file:** two auditor categories — (a) flag services with unquoted spaced binPaths
whose resolution root is user-writable; (b) inventory the two AlwaysInstallElevated
policy values. Both are pure enumeration, no new sensors needed.

**Cleanup:** `sc.exe delete CCDCUnq`; `Remove-Item C:\Users\Public\My.exe`; remove both
AlwaysInstallElevated values.
