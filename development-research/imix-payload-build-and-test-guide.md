# Building & Testing Real imix (Realm) Payloads on Windows — Manual EDR Verification Guide

> **Purpose:** Build genuine Realm imix implants for Windows, launch them on this machine, and
> manually verify the CCDC EDR detects them — both at launch and while running. Every build
> variation below is paired with the EDR rule(s) that should fire, so a miss is immediately
> actionable detection-engineering work, not a surprise.
>
> **Scope:** Realm/imix is an open-source (GPL-3.0) adversary-emulation framework
> ([spellshift/realm](https://github.com/spellshift/realm), [docs.realm.pub](https://docs.realm.pub)).
> This guide is for authorized defensive testing on hardware you own, in an isolated lab
> network, with the Tavern server and implant on the same segment. The callback URI is baked
> into the binary — never point a build at anything outside the lab.

---

## 1. Prerequisites

- Windows target: this server, with the EDR running (`python -m edr`, console at http://127.0.0.1:8420)
- Build box: the repo's devcontainer, or any machine with **Go ≥1.21** and a **Rust toolchain**
  (`rustup`; add the `x86_64-pc-windows-gnu` or `msvc` target as appropriate)
- Isolated network: host-only/inner vswitch, or at minimum the Tavern bound to loopback

## 2. Build the Tavern server

```bash
git clone https://github.com/spellshift/realm.git && cd realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern
```

The server's public key is auto-served at its `/status` endpoint — the implant build fetches
it automatically when building against a directly reachable Tavern.

## 3. Build imix payloads for Windows

All builds happen in `implants/imix/`. Configuration is **compile-time via environment
variables** (documented in the [imix user guide](https://docs.realm.pub/user-guide/imix)):

| Env var | What it sets |
|---|---|
| `IMIX_CALLBACK_URI` | C2 address, e.g. `http://192.168.x.x:8080` (or loopback for the lab) |
| `IMIX_SERVER_PUBKEY` | Server public key (auto-fetched from `/status`; set manually if using a redirector) |
| `IMIX_CONFIG` | Path to a YAML config for multi-transport setups |
| `IMIX_GUARDRAILS` | Exit unless a file/process/registry condition passes |
| `IMIX_UNIQUE` | Host-uniqueness selectors (env, file, MAC, registry) |

### P1 — baseline gRPC implant (your primary test)

```bash
cd implants/imix
IMIX_CALLBACK_URI=http://127.0.0.1:8080 cargo build --release
# -> target/release/imix.exe
```

Copy `imix.exe` to `%TEMP%\sysupd.exe` on the target and run it. **Expected EDR behavior:**

| Stage | Rule(s) that should fire | Sensor |
|---|---|---|
| File lands in %TEMP% | `SIG-REALM-IMIX` + `SIG-RUST-IMPLANT` (critical/high) | signature scanner, on-write/interval |
| Process launches from %TEMP% | `EVT-4688-TEMP` (high) | kernel-fed Security 4688 |
| Launch-time image scan | `PROG-IMPLANT-LAUNCH` (critical) + SIG rules again | WMI poll / 4688 image scan |
| While running, calling back | `NET-BEACON` (critical) once cadence stabilizes | beacon-cadence analysis |
| Console | live panel + Alerts screen show the chain | — |

### P2 — stripped build (tests signature robustness)

```bash
cargo build --release
strip target/release/imix.exe     # or: cargo strip
```

Symbol stripping removes some debug/string surface but **not** the compiled-in config strings
(`IMIX_CALLBACK_URI` etc. survive in `.rodata` because they're runtime env lookups). The
family rule should still hit. If it doesn't, your rule is string-fragile — add the
`SIG-RUST-IMPLANT` heuristic strings as backstop weights.

### P3 — Windows service build (persistence test)

```bash
cargo build --release --features win_service
```

Install and start it:

```powershell
sc create CCDCImixTest binPath= "C:\Users\Public\imix_svc.exe"
sc start CCDCImixTest
```

**Expected:** `EVT-7045` + `PERS-SERVICE` (critical) from the System log and the persistence
auditor's baseline diff — this should alert within one 30s audit cycle *and* at install time.

### P4 — DLL build (LOLBIN loading test)

Build the library target and load it via a signed interpreter:

```powershell
rundll32 C:\Users\Public\imix.dll,Start
```

**Expected:** `PROC-RUNDLL-NOARG` (medium) fires if launched argument-less; the DLL write to
`C:\Users\Public` triggers `SIG-REALM-IMIX` on scan; the `rundll32` child of Explorer gets the
`PROC-SUSP-PARENT` (critical) parent-child check.

### P5 — HTTP transport variant

```bash
IMIX_CALLBACK_URI=http://127.0.0.1:8080 IMIX_CONFIG=http.yaml cargo build --release
```

with `http.yaml` selecting the `http1` transport with `interval: 10, jitter: 0.3`.
**Expected:** same SIG/launch chain; `NET-BEACON` on the cadence; egress visible in the flow
sensor as cleartext HTTP to one peer.

## 4. imix's own evasion/stealth options — and what your EDR should still catch

These are imix's documented operational features, not EDR-exploitation. For each: the point
of testing it is confirming the *behavioral* detections hold when static ones weaken.

| Option | How to build/run | What it evades | What must still fire |
|---|---|---|---|
| **Guardrails** (`IMIX_GUARDRAILS`) | Set a file-exists condition; run on wrong host → implant exits silently | Sandboxes/analysts that execute samples off-target | Launch telemetry is independent of survival: `EVT-4688-TEMP` + image scan still log the attempt (this is your P9 negative test — the EDR must record the launch even though the process dies in <1s) |
| **Uniqueness selectors** (`IMIX_UNIQUE`) | MAC-address selector, file selectors removed for stealth | Sample reuse across hosts | Nothing to catch at runtime, but the binary still carries `IMIX_*` strings → SIG rules on write |
| **Jittered callbacks** | `jitter: 0.5` in transport config | Naive fixed-interval beacon detectors | Your cadence analyzer tolerates jitter — verify `NET-BEACON` still fires at 0.5 jitter; if not, widen the tolerance window |
| **DNS/ICMP transports** | `IMIX_CONFIG` YAML with `dns` (TXT) or `icmp` transport | Port/protocol allow-listing, TCP-centric flow analysis | Not yet covered — **known gap**; a DNS-TXT test build is the highest-value negative test you can run |
| **`tcp_bind` inverted channel** | YAML with `tcp_bind` on a high port | Egress filtering (implant listens, doesn't connect) | Not yet covered — add a rule: non-service process binding a listener on a non-standard port |
| **QUIC port rebinding** | `rebind_interval` in QUIC transport | Flow correlation keyed on (IP, port) | Your flow analysis keys on IP — verify; if it keys on IP+port anywhere, rebind defeats it |
| **`install` subcommand** | `imix.exe install` (runs embedded `main.eldritch` tomes) | Nothing specific — it *creates* persistence | Persistence auditor diff: whatever the tome drops (service/cron-equivalent/task) must alert within one audit cycle |

**Deliberately not included:** loader/packer wrapping, signer abuse, or anything targeting
your EDR's specific sensor mechanisms. imix doesn't ship those, and hand-rolling them isn't
needed to validate your detection coverage — the framework's own options exercise every
detection layer you built.

## 5. Manual test procedure (per payload)

1. Confirm the EDR is up: `curl http://127.0.0.1:8420/api/state` shows climbing event counts
   and the kernel trace active.
2. Start Tavern on the build/lab box; note the callback URI you compiled in.
3. Drop the payload **from a normal user context** (copy, browser-download-style) — don't
   skip the drop stage; you're testing on-write scanning too.
4. Launch it. Keep the process alive (gRPC default callbacks keep it resident).
5. Watch the console's live panel and the Alerts screen. Verify each expected rule from the
   tables above fires, in roughly the documented order (write-scan → launch → resident →
   beacon cadence).
6. Check the **kill chain correlation**: the Dashboard's right rail should let you walk the
   same implant's write → launch → callback as one story.
7. Record time-to-visible for each stage (target < 10s for file/launch, < ~90s for beacon
   cadence — it needs several intervals to establish periodicity).
8. After the run: stop the implant, delete artifacts, re-baseline via the console's
   baseline action so the next audit cycle doesn't re-alert on leftovers.
9. Any **miss** → note the build flags, grab the binary and a memory dump, and add/tune the
   rule — that binary goes into your regression corpus.

## 6. Cleanup and hygiene

- `sc delete CCDCImixTest` for the service test; remove dropped files from `%TEMP%`/Public
- Re-POST `/api/baseline` after cleanup
- Keep lab builds out of any directory the scanner allow-lists implicitly (Program Files) —
  test realism requires the drop zones red teams actually use
- Save each build variation with its compile flags recorded; the corpus is only useful if
  you can reproduce why a rule missed

## 7. Expected gaps this testing will expose (pre-filed, not failures)

1. **DNS/ICMP transports** — no sensor coverage yet; treat a miss here as backlog, not a bug
2. **tcp_bind listener detection** — needs the new non-service-listener rule
3. **Memory scanning** — your EDR scans the on-disk image, not process memory; imix doesn't
   encrypt its memory (no sleep obfuscation), so a memory-scan feature would find the same
   strings — worthwhile next build item
4. **Config extraction automation** — the callback URI is recoverable via `strings`; wiring
   that into the quarantine action automates egress blocking

## Sources

- [spellshift/realm](https://github.com/spellshift/realm)
- [Realm imix user guide](https://docs.realm.pub/user-guide/imix) — build env vars, transports, guardrails
- [docs.realm.pub](https://docs.realm.pub/) — Tavern setup, Eldritch docs
- Companion docs in this repo: `realm-implant-test-payload-guide.md` (simulant matrix),
  `edr-live-test-report.md` (current detection coverage)
