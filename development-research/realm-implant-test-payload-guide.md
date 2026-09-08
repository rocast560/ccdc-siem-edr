# Realm C2 (imix) — Test Payload & Detection Verification Guide

> **Purpose:** Build real imix implants in a lab, launch them against your EDR, and verify your YARA rules + behavioral detections catch (a) the implant executing on a host and (b) new implant binaries at write/launch time. Companion to `red-team-c2-evasion-persistence-detection-guide.md` §3.4.
>
> **Lab safety:** All of this happens in an isolated VM network (host-only/inner virtual switch) with the Tavern server and target VMs on the same lab segment. Never point test implants at anything outside the lab — the callback URI is baked into the binary.

---

## 1. What imix Actually Is (Detection-Relevant Facts)

From the [repo](https://github.com/spellshift/realm) and [docs.realm.pub](https://docs.realm.pub/user-guide/imix):

- **Single Rust implant, cross-platform:** Windows (`imix.exe`, `imix.dll`, a Windows-service build via `--features win_service`), Linux (static via musl), macOS. One codebase — one good YARA family rule can cover all platforms.
- **No built-in command set.** imix fetches **Eldritch tomes** (Starlark-like scripts) from the **Tavern** server and executes them. So post-exploitation behavior is fully scriptable — you cannot rely on "known command" signatures; you must detect the *substrate* (binary, callback behavior, injection primitives like the Eldritch reflective DLL loader).
- **Configuration is compiled in** via env vars: `IMIX_CALLBACK_URI`, `IMIX_SERVER_PUBKEY`, `IMIX_GUARDRAILS`, `IMIX_CONFIG`, `IMIX_UNIQUE`, with runtime overrides `IMIX_BEACON_ID` / `IMIX_LOG`. These env-var names and the YAML/URI strings typically survive in the binary — your config-extraction and YARA goldmine.
- **Transports:** gRPC (default, TLS), HTTP/1.1, QUIC, DNS (TXT/A/AAAA), ICMP, and `tcp_bind` (agent listens for inbound chaining). gRPC and QUIC also carry reverse shell and SOCKS5.
- **Callback discipline:** fixed `interval` + `jitter` (0.0–1.0) per transport, QUIC port rebinding (`rebind_interval`/`rebind_jitter`) — beacon periodicity detection must tolerate the configured jitter.
- **Crypto:** ChaCha20; server pinned by public key. Egress looks like encrypted gRPC/HTTP2 frames to one host.
- **Evasion posture:** Realm/imix is *not* primarily an EDR-evasion tool (no sleep obfuscation, no indirect syscalls out of the box). It evades by **looking like nothing in particular**: an unsigned Rust binary with quiet C2. Your detections should therefore be (1) static binary anomaly + YARA, (2) network behavioral, (3) the injection primitives its tomes invoke (reflective DLL loader), and (4) persistence via the `install` subcommand.

---

## 2. Build the Test Corpus

In the devcontainer (or any box with Go + Rust):

```bash
git clone https://github.com/spellshift/realm.git && cd realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern                     # start server; note its address + public key
```

Then in `implants/imix/`, build a matrix of payloads. Every variant is a row in your test matrix — **build each with a distinct callback interval so you can verify your periodicity detector resolves the difference**:

| # | Build | Purpose — what it tests |
|---|---|---|
| P1 | `cargo build --release` (default exe, gRPC) | Baseline: unsigned-Rust-binary YARA + gRPC egress detection |
| P2 | Windows DLL build (`imix.dll`) + `rundll32` invocation | DLL loaded by LOLBIN — your module-load/parent-child telemetry |
| P3 | `--features win_service` + `sc create` install | Service persistence — events 7045, service binPath anomaly, persistence auditor |
| P4 | Static Linux musl build, copied to an Ubuntu target | Linux sensor: unsigned static ELF, high entropy, cron/systemd install |
| P5 | HTTP/1.1 transport (`IMIX_CONFIG` YAML) | Plain-HTTP egress — URI/UA/entropy checks, cleartext structure |
| P6 | QUIC transport with `rebind_interval` set | UDP 443 QUIC + port-hopping — flow/periodicity detection under rebinding |
| P7 | DNS TXT transport | DNS-tunnel detection: TXT query volume/entropy per second-level domain |
| P8 | ICMP transport | Non-standard ICMP payload sizes/content to a single peer |
| P9 | `IMIX_GUARDRAILS` set to a file that doesn't exist | Implant exits silently — verify your EDR still logged the launch attempt |
| P10 | `IMIX_UNIQUE` with default (file-based) selectors | Disk artifacts from uniqueness checks — file-write telemetry |
| P11 | Reverse shell tome over gRPC | Long-lived connection + shell-like child process patterns |
| P12 | SOCKS5 proxy tome | Implant process opening many outbound connections (proxy artifact) |
| P13 | Eldritch reflective-DLL-loader tome | Injection primitives — your VirtualAlloc/RWX/section telemetry |
| P14 | `imix install` with embedded `main.eldritch` tome | Persistence execution — auditor diff + process-tree detection |
| P15 | Copy of P1 with `strip` + a few bytes patched (rename section, change icon) | YARA robustness — rules must not be single-string-fragile |

Also save, for the corpus: the raw P1/P4/P5 binaries (YARA regression), a PCAP of each transport, and full memory images of a running P1 (on-write scanning tests).

---

## 3. YARA Rules to Verify

Write these, then run `yara -r` over the corpus. Strings below are sourced from the documented env/config surface; **verify each against your own built binaries** (Rust string tables shift between releases — treat this as tuning data, not gospel).

### 3.1 Family rule — Realm imix config surface

```yara
rule Realm_Imix_Implant
{
    meta:
        author = "blue team"
        description = "Realm C2 imix implant - config/env strings and eldrift artifacts"
        reference = "https://github.com/spellshift/realm"
    strings:
        $env1 = "IMIX_CALLBACK_URI" ascii
        $env2 = "IMIX_SERVER_PUBKEY" ascii
        $env3 = "IMIX_BEACON_ID" ascii
        $env4 = "IMIX_GUARDRAILS" ascii
        $env5 = "IMIX_CONFIG" ascii
        $eld1 = "main.eldritch" ascii
        $eld2 = "eldritch" ascii
        $eld3 = "tavern" ascii
    condition:
        uint32(0) == 0x00905a4d or uint32(0) == 0x464c457f   // PE or ELF
        and 3 of ($env*)
        and 1 of ($eld*)
}
```

Expected: fires on P1–P15 unless heavily modified. P15 (stripped) may drop to 2-of-3 env strings — if it misses, relax to `2 of ($env*)` and weight conditionals on the Rust heuristic below instead.

### 3.2 Rust implant heuristic (catches stripped/modified builds)

```yara
rule Unsigned_Rust_Binary_Suspicious
{
    meta:
        description = "Rust-compiled binary with no version info and C2-ish imports - candidate implant"
    strings:
        $rust1 = "rust_begin_unwind" ascii
        $rust2 = "panicked at " ascii
        $rust3 = "/rustc/" ascii
        $rust4 = ".rs" ascii wide
        $net1 = "Connect" ascii
        $net2 = "TcpStream" ascii
        $tls1 = "chacha" ascii nocase
    condition:
        uint32(0) == 0x00905a4d or uint32(0) == 0x464c457f
        and 2 of ($rust*)
        and 1 of ($net*, $tls1)
        and not filesize < 200KB
        // tune: unsigned check is your EDR's job via signature/authenticode lookup;
        // pass that verdict into the scan pipeline rather than encoding it here
}
```

This is deliberately noisy alone — the point is that on a CCDC gold image the population of *unsigned Rust binaries* is near zero, so operator triage is one click. Wire the verdict into your alert, don't fight for zero FPs inside YARA.

### 3.3 Static-musl Linux build

```yara
rule Realm_Imix_Static_Musl_ELF
{
    strings:
        $musl1 = "musl" ascii
        $env1 = "IMIX_CALLBACK_URI" ascii
        $env2 = "IMIX_BEACON_ID" ascii
        $eld1 = "eldritch" ascii
    condition:
        uint32(0) == 0x464c457f
        and $musl1
        and 1 of ($env*)
        and $eld1
}
```

### 3.4 Eldritch tome files (on-write detection)

```yara
rule Eldritch_Tome_Script
{
    strings:
        $t1 = "eldritch" ascii
        $t2 = "def " ascii
        $t3 = "load_library" ascii
        $t4 = "reflective" ascii nocase
        $t5 = "reverse_shell" ascii
    condition:
        filesize < 1MB and 2 of them
}
```

Tomes written to disk (via `install` or embedded-file extraction) are caught at write time by your on-write YARA hook — a much earlier tripwire than memory detection.

### 3.5 Verification procedure

1. `yara realm_rules.yar corpus/` — every P* binary must match ≥1 rule; record which.
2. False-positive sweep: run the same rules over `C:\Windows\System32`, `C:\Program Files`, `/usr/bin`, and every binary on your CCDC gold image. Any hit = tuning input.
3. Robustness: for P15 (stripped/mutated), confirm which rule still fires; if none, your detection is string-fragile — add the Rust-heuristic as backstop.
4. Wire into EDR: confirm the on-write scan path (minifilter/ETW file IO) invokes these rules and that the *launch* path (image-load) re-scans before execution — that's your "trying to be launched" gate. Block + quarantine + alert with full path and hash.

---

## 4. Runtime Detection Tests (Implant Already Running)

For each payload, launch it with your EDR active and verify the specific telemetry fires:

| Test | Expected detection | Verify in your console |
|---|---|---|
| P1 running, gRPC callback every 30s ± jitter | Network periodicity: autocorrelation peak at 30s with jitter spread; single dst host, TLS, non-browser JA4 | Net-flow + TLS fingerprint panels |
| P1 process inspection | Unsigned Rust binary in memory; module list has no matching on-disk story if DLL-injected variants used | Memory scan on process, YARA over dumped regions |
| P2 `rundll32` loading `imix.dll` | Parent-child anomaly (`explorer→rundll32` no args) + DLL load from user-writable path + unsigned | Image-load telemetry |
| P3 service install | Event 7045 + your service-creation hook + binPath in user dir | Persistence auditor diff |
| P5 HTTP transport | Cleartext HTTP to single host, fixed-path requests, encrypted bodies (high-entropy POST bodies) | HTTP inspection layer |
| P6 QUIC + rebinding | UDP flows to same host across changing ports at rebind interval | Flow tracker keyed on (dst IP), not (dst IP,port) — **port rebind will defeat port-keyed correlation; key on IP** |
| P7 DNS TXT | TXT-query rate per domain > threshold; label entropy; single NS destination | DNS monitoring (SIEM sensor) |
| P8 ICMP | ICMP packets with payload > 64 bytes to one external IP, periodic | Flow sensor |
| P11 reverse shell | Long-lived connection + child process (`cmd.exe`/`bash`) under implant | Process tree telemetry |
| P12 SOCKS5 | Fan-out: one process, many concurrent outbound connections to internal IPs (lateral movement precursor) | Per-process connection counting |
| P13 reflective DLL loader tome | RWX allocation, `LoadLibrary`-absent module execution — your §2.1 injection telemetry | Hook layer + memory scan |
| P14 `install` | New persistence artifacts (whatever the embedded tome drops: service, cron, unit file, `authorized_keys` append) | Persistence auditor diff vs baseline |
| P9 guardrail-fail exit | Implant launched and exited within seconds — verify launch was still logged (image-load event exists even though process dies) | Process telemetry completeness |

**Key negative test:** P9 matters more than it looks. An EDR that only reports long-lived or network-active processes will miss throwaway implant executions. Your image-load/process-create telemetry must be complete and independent of the implant surviving.

---

## 5. Config Extraction (Incident Response Workflow)

When your EDR quarantines a binary, extract the baked-in config to immediately block egress:

1. `strings -n 8 imix.exe | grep -E "IMIX_|eldritch|http|grpc"` — callback URI, config YAML fragments, guardrail selectors are typically recoverable.
2. Parse `IMIX_CALLBACK_URI` → add the host/IP to the SIEM blocklist and hunt retroactively for other hosts that contacted it (your netflow history becomes a compromise census).
3. The compiled-in server public key and beacon ID let you correlate multiple callbacks to one campaign.

Build this into the EDR's quarantine action as an automated step (strings extraction is fine; the config surface is plain ASCII in release builds).

---

## 6. What imix Will *Not* Trigger (Know Your Gaps)

- **No sleep obfuscation / memory encryption** — a straightforward periodic memory scan of the implant process finds it; you don't need wake-transition tricks (those are for Havoc/CS). Don't skip building them for Realm's sake, but know they're not exercised here.
- **No indirect syscalls / API unhooking** — your userland hooks see normal traffic from imix itself. (A tome *could* load a loader that does; P13 approximates this.)
- **Tomes are arbitrary** — any behavior expressible in Eldritch (proc enumeration, file ops, SSH lateral movement) can be tasked. Your behavioral detections (process tree, file writes, connection fan-out) are the coverage, not command signatures.
- **tcp_bind transport** — implant *listens* inbound. Add a detection for non-service processes binding listeners on non-standard ports; at CCDC this also catches netcat-style backdoors.

---

## 7. CI Regression

Freeze the corpus (P1–P15 binaries + PCAPs + memory dumps) in the repo (git-crypt or similar if you don't want live samples browseable). On every EDR build:

1. YARA suite over the binary corpus — assert 100% detection except documented-mutated P15.
2. Replay PCAPs through the network sensor — assert periodicity/DNS/ICMP alerts fire.
3. Rescan memory dumps through the scanner service — assert the implant region is flagged.
4. Measure end-to-end time from artifact write → console visibility; target < 10s at CCDC.

Sources: [spellshift/realm](https://github.com/spellshift/realm), [Realm docs — imix user guide](https://docs.realm.pub/user-guide/imix), [docs.realm.pub](https://docs.realm.pub/).
