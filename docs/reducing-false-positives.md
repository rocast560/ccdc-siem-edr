# Reducing False Positives — CCDC-EDR Tuning Guide

False positives don't just waste time — at CCDC they cost placement points by
burying the real red-team detections during triage. This guide documents the
techniques implemented in this EDR (`edr/tuning.py` and friends), why each
exists, and the workflow for tuning anything new.

## What's already implemented

### 1. Sensor self-exclusion (`tuning.SELF_PATTERNS`)
**Problem:** the EDR's own tooling (wevtutil, `Get-CimInstance` PowerShell,
netstat, logman) spawns processes every few seconds whose command lines trip
the same rules meant for attackers — the single largest FP source observed.

**Fix:** `rules.evaluate()` drops any event whose command line matches the
sensor-noise patterns (wevtutil qe, Win32_ CIM queries, netstat -ano, etc.).

**Tuning:** if a *new* sensor spawns processes with distinctive commands, add
the pattern to `SELF_PATTERNS`. Keep patterns specific — `netstat -ano`, not
`netstat`.

### 2. Trusted-path scoping (the "installed software" principle)
**Problem:** browsers, IDEs, terminals, and OS telemetry legitimately do
everything attackers do: periodic HTTPS keepalives (beacon-like cadence),
cross-process handles (debuggers/consoles), listeners on high ports
(per-user installed apps).

**Fix:** behavioral alerts (`NET-BEACON`, `PROC-XHANDLE`, `NET-LISTENER`)
only fire when the acting process runs from an **attacker-writable path**.
`c:\windows`, `c:\program files`, and per-user install roots
(`\appdata\local\programs\`, `\appdata\local\microsoft\`) are trusted; TEMP,
`c:\users\public`, ProgramData, and arbitrary user paths are not.

**Why path and not signatures:** authenticode checks need wintrust plumbing
and still allow attacker-signed binaries; path provenance is the cheaper
proxy that matches how implants actually land.

**Tuning:** `tuning.LISTENER_ALLOW_NAMES` / `LISTENER_ALLOW_PREFIXES` for
known dev tools on your box; `handles.ALLOWED_PREFIXES/INFIXES` and
`network.TRUSTED_IMG_*` for the same.

### 3. Loopback scoping for listeners
Loopback-only binds (`127.0.0.1`) are dev servers, not exposed backdoors —
`NET-LISTENER` only flags non-loopback binds.

### 4. Alert cooldown / dedup (`tuning.repeat_or_none`)
**Problem:** recurring conditions (a pipe that exists, a periodic listener)
re-alert every sensor cycle, flooding the queue.

**Fix:** `raise_alert` keys each alert on `(rule, entity)` — pipe/peer/port
first, else pid+path — and within **10 minutes** a repeat increments the
original alert's `repeat` counter instead of stacking a duplicate.

**Gotcha we hit:** keying on a bare path is wrong — every child of the same
interpreter shares it, collapsing unrelated events. Paths only count when
combined with the pid.

### 5. Scope narrowing on noisy detectors
- `HOOK-DLL` correlation only counts modules in genuinely writable paths
  (Microsoft-managed AppData and WindowsApps are excluded).
- JIT hosts (.NET, java, node) are allowlisted for all memory heuristics.
- Beacon cadence on loopback peers is downgraded to high (lab concession).

## The workflow for anything new

1. **Measure first.** Which rule floods? `GET /api/state` and count by rule
   over 10 minutes of normal-machine idle. One-off alerts are not FPs.
2. **Classify before suppressing.** For each alert: true positive, benign
   true positive (the behavior happened, a trusted process did it), or false
   positive (detection logic wrong)? Only the second deserves scoping.
3. **Scope by provenance, not by behavior.** Prefer "alert only when the
   actor runs from a writable path" over "add this exe name to a list" —
   names are spoofable, paths where software legitimately installs are not.
4. **Suppress at the narrowest layer.** Rule-level `evaluate()` skip >
   sensor-level scope > entity allowlist > rule toggle in the console.
   The console toggle (Signatures screen) is the break-glass option.
5. **Re-run the suites.** `EDR_TESTS=classic python tests/run_tests.py`,
   `python tests/run_tranche4/5.py` — every suppression has broken a real
   detection at least once in this project's history. If a test now fails,
   your scope is too broad.
6. **Log what you suppressed.** Keep the reason in the alert's `why` text or
   the code comment next to the allowlist entry — future-you is the reader.

## Techniques deliberately NOT used here

- **ML-based FP reduction** — needs training volume a CCDC team never has.
- **Auto-suppression from ack history** — a red teamer who sees you ack a
  pattern once owns you. Suppression decisions are code, reviewed by humans.
- **Signature (authenticode) gating** — engineering cost exceeds its
  discriminative value at this scale; path provenance covers the same ground.

## Known FP characteristics of current rules

| Rule | Benign sources seen | Mitigation in place |
|---|---|---|
| NET-BEACON | IDE/browser telemetry keepalives | trusted-path scope |
| PROC-XHANDLE | terminals, debuggers, IDE child management | trusted-path scope + per-owner budget |
| NET-LISTENER | per-user installed app ports | loopback + allowlist + trusted-path |
| HOOK-DLL | Microsoft-managed shared DLLs | writable-path-only correlation |
| MEM-RWX-* | JIT runtimes | JIT host allowlist |
| PROC-MASQ | admin tooling copies of system exes | none — review manually; genuinely rare |
| TIME-STOMP | installers that backdate stamps deliberately | review; installer paths could be scoped |
