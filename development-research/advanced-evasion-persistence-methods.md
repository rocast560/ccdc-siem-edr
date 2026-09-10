# Advanced Evasion & Persistence Methods — Windows and Linux (2025–2026 research)

Companion to the existing guides (`c2-frameworks-detection-guide`,
`linux-persistence-evasion-guide.md`, `playbooks/README.md`). This doc covers
the advanced tier BEYOND what our sensors and playbooks already exercise,
with three columns per technique: what it is / how defenders catch it /
**where this EDR stands** (have · partial · ceiling) — plus a shortlist of
concrete detection upgrades this research justifies.

---

## Part A — Windows

### A1. Indirect syscalls (the evolution past direct syscalls)

Direct syscalls (`syscall` in private memory) skip EDR userland hooks but are
trivially flagged — our `SYSCALL-STUB` rule exists for exactly that.
**Indirect syscalls** instead jump INTO a legitimate syscall instruction
inside ntdll, so the execute happens from a signed image and the call stack
looks conventional ([Dark Relay — Stealth Syscalls & EDR
Bypass](https://www.darkrelay.com/post/stealth-syscall-execution-bypass-edr),
[CovertSwarm — evolution timeline of EDR
bypasses](https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques),
[CyberKach — indirect syscalls](https://www.cyberkach.com/blog/indirect-syscalls-heaven-for-hackers-hell-for-defenders)).

**Detection**: stack-based analysis — "ghost hunting" theory
([FluxSec](https://fluxsec.red/edr-syscall-hooking)): walk the thread stack;
an indirect call into ntdll's stub from a private/unbacked return address is
the tell. Reference: [0xdbgman — EDR
internals](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/).

**EDR status: partial.** `STACK-UNBACKED` checks return addresses into
private exec memory — catches naive indirect calls. Defeated by **thread
stack spoofing** (fake frames pushed onto a spoofed stack) — that is a
documented ceiling for a userland-only sensor.

### A2. ETW/AMSI in-process patching

Patching `EtwEventWrite`'s prologue (or AMSI's) inside your own process
mutes the sensor's telemetry at the source. Kernel ETW-TI requires PPL
signing — already documented as our hard ceiling. In-process ETW patching of
the .NET runtime is visible as **image-backed memory that no longer matches
disk**.

**Detection**: .text-vs-disk comparison at runtime.

**EDR status: partial — `NTDLL-TAMPER` does exactly this check, but only
for ntdll.** Upgrade A-shortlist #1: generalize the .text-vs-disk
comparison to every loaded module (catches ntdll AMSI/ETW patches, module
stomping, and hooked-API restoration in one rule).

### A3. Module stomping / DLL stomping

Load a legitimate signed DLL (ideally one nobody uses, e.g. an old
`dbghelp` variant), then overwrite its `.text` in memory and execute from
it — code runs from a signed, image-backed path, defeating both
unbacked-memory and signature checks.

**Detection**: same generalized .text-vs-disk comparison; also
loads of rare signed DLLs from unusual processes (module-load baselining).

**EDR status: ceiling → fixable with upgrade #1.** This is the strongest
argument for that upgrade.

### A4. Registry persistence without registry callbacks — NTUSER.MAN

The profile `NTUSER.MAN` hive is loaded for the user at logon; planting
persistence values there **never triggers `CmRegisterCallback`-based EDR
telemetry** because the writes happen through hive-load, not registry APIs
([Deceptiq — NTUSER.MAN registry
persistence](https://deceptiq.com/blog/ntuser-man-registry-persistence),
[dev.to — EDR blind spots: kernel
callbacks](https://dev.to/harsh_hak/edr-blind-spots-kernel-callbacks-5ae7)).
Related exotica is tracked by [Nextron's registry-persistence
detection work](https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/)
and [Elastic's uncommon-registry-change rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_registry_uncommon).

**Detection**: treat the hive FILE as the sensor surface — hash/watch
`%USERPROFILE%\NTUSER.MAN` (it should barely ever exist/change), plus
file-level auditing on profile dirs.

**EDR status: gap.** Our persistence auditor enumerates registry via APIs;
it never looks at NTUSER.MAN. Upgrade A-shortlist #2: persistence auditor
flags existence/change of any NTUSER.MAN + baseline-hashes profile hives.

### A5. Callback/VFH execution & thread hiding

Callback-based execution (`EnumWindows`, cert-store callbacks, fiber and
thread-pool callbacks) starts execution from legit framework entry points,
so "thread start address in private memory" checks whiff. Thread-hide
(`HideFromDebugger` via ThreadHideFromDebuggerInformation class) and VEH
handler abuse round out the family.

**EDR status: partial.** THREAD-UNBACKED catches injected threads whose
start address is private, but callback-spawned execution starts inside
signed DLLs — the behavioral signal moves to *what the thread then does*
(our memory/cadence layers). Ceiling documented.

### A6. Process herpaderping / doppelgänging (TxF)

Write payload, swap the on-disk content after the image is mapped —
signature scanners see one file, the kernel executes another. TxF
doppelgänging is the older sibling.

**EDR status: ceiling** (needs file-system filter driver). Mitigation note:
our memory-side signature scan (`memscan`) still sees the real bytes in
memory — defense-in-depth already present.

### A7. UAC auto-elevate bypasses (maintenance-access quick hits)

`fodhelper`/`computerdefaults`-style probes write HKCU
`Software\Classes\ms-settings\Shell\Open\command` then launch an
auto-elevate binary. Cheap, loud in the registry, and a common red-team
opener against admin sessions.

**EDR status: gap (cheap fix).** Upgrade A-shortlist #3: rule on creation
of `HKCU\...\ms-settings\*` (and `HKCU\...\Cube99`, `DelegateExecute`
tweaks) from 4688/registry telemetry. Almost zero FP surface.

### A8. BYOVD (kernel)

Bring-your-own-vulnerable-driver to kill EDR drivers from the kernel —
publicly accelerating (see the SPECTRE implant research in the commercial
EDR doc). **Ceiling** for us (no kernel presence); note as inherent risk of
userland-only sensors and move on.

---

## Part B — Linux

### B1. eBPF backdoors — the BPFDoor family (the advanced watershell)

Passive, magic-byte-woken backdoors that never open a port: an eBPF filter
(or classic BPF socket filter, like watershell-cpp) sniffs all traffic and
spawns a shell only when a magic packet arrives. 2025–26 lineage: **BPFDoor**
([MITRE S1161](https://attack.mitre.org/software/S1161/), [Trend Micro —
hidden controller](https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html),
[Rapid7 — telecom sleeper cells](https://www.rapid7.com/blog/post/tr-bpfdoor-telecom-networks-sleeper-cells-threat-research-report/)),
**J-magic**, **Symbiote**, **LinkPro** ([Synacktiv
analysis](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)),
ebpfkit.

**Detection — the consensus is LOAD-TIME, not runtime**
([Datadog — detection primitives for eBPF
rootkits](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/),
[eBPF backdoor detection
framework](https://windshock.github.io/en/post/2025-04-29-ebpf-backdoor-detection-framework/),
[FortiGuard — eBPF filters for Symbiote/BPFDoor](https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware),
[Sandfly — eBPF rootkit
incident](https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis)):

1. auditd on the `bpf`/`perf_event_open` syscalls from non-privileged
   contexts; alert on `bpftool`/`tc` execs:
   ```
   -a always,exit -F arch=b64 -S bpf -k ebpf
   -a always,exit -F arch=b64 -S perf_event_open -k ebpf
   ```
2. enforce + alarm on `kernel.unprivileged_bpf_disabled` flipping to 0.
3. inventory eBPF programs (`bpftool prog show`) in your baseline; new
   programs = incident. Attach-type anomalies (XDP/tracepoint on
   security-critical hooks) are the Datadog primitives.

**EDR status (Windows analogue): partial.** Our `PKT-SOCKET` +
`SIG-WATERSHELL` + `SIG-MINGW` rules catch the non-eBPF cousins; on Linux
images, the auditd rules above are the detection.

### B2. Interpreter & package-manager persistence (no root binary needed)

Config-level backdoors that never touch cron/systemd: `sitecustomize.py`
(auto-imported by every python), `PYTHONSTARTUP`, R's `Rprofile.site`,
`NODE_OPTIONS=--require`, shell `ENV`/`BASH_ENV`, **gcc `specs` file**
(compiler that backdoors everything it builds), **apt hooks**
(`/etc/apt/apt.conf.d/` `Pre-Invoke`), **dpkg diversions**, RPM `%post`
scriptlets. Detection = auditd path watches:

```
-w /usr/lib/python3/dist-packages/sitecustomize.py -p wa -k interp
-w /etc/R -p wa -k interp
-w /etc/apt/apt.conf.d/ -p wa -k pkg-hooks
-w /usr/lib/rpm/macros -p wa -k pkg-hooks
```

**EDR status: gap on Linux** (add rules above to the guide's baseline);
the Windows cousins (.NET profiler/CLR hijack, PowerShell profiles) ARE
audited by our persistence auditor.

### B3. sshd itself as the backdoor

`AuthorizedKeysCommand` swapped to an attacker script, `Match` block with
`ForceCommand` to a wrapper, or `PermitRootLogin` quietly re-enabled.
Detection: auditd on `/etc/ssh/` (already in the guide's baseline) PLUS a
**semantic check**: diff effective `sshd -T` output against the baseline
(`sshd -T | sha256sum` in a watchdog cron) — config-file byte-level diffs
miss equivalent-but-reordered files.

### B4. systemd beyond units: generators, tmpfiles, environment.d

`/run/systemd/system-generators/*` re-create units each boot (survives
`systemctl disable`); `tmpfiles.d` snippets can recreate payloads or chmod
SUID at boot; `environment.d` injects `LD_PRELOAD` per user session. All
are file-drops in watched dirs — the guide's auditd `systemd` key catches
them IF extended:

```
-w /run/systemd/ -p wa -k systemd
-w /etc/tmpfiles.d/ -p wa -k systemd
-w /root/.config/environment.d/ -p wa -k shellhijack
```

### B5. Userland hiding: bind-mounts over /proc and files

`mount --bind /dev/null /proc/<pid>/cmdline`-style hides, or overwriting
`/etc/passwd` view with a bind-mounted clean copy. Invisible to in-host
tools reading the overlaid path — the counter is **cross-view
verification** (compare `getent` vs raw `/etc/passwd` read, `ps` vs
`/proc` scan) from a second vantage point. That is why agentless scanning
keeps beating in-host rootkit checks ([Sandfly's
approach](https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis)).

**CCDC practical**: keep a known-good live-USB/container and diff the
target's `/etc` and `/proc` listings from it.

### B6. Initramfs persistence

Payload rebuilt into the initramfs executes before the real root mounts.
Detection: hash `/boot/initrd*` in the baseline; regenerate from trusted
packages when in doubt. Deep-dive defense — listed for completeness.

---

## Detection upgrade shortlist (what this research justifies)

| # | upgrade | source technique | effort |
|---|---|---|---|
| 1 | Generalize `.text`-vs-disk to ALL loaded modules (module stomping, ETW/AMSI patch detection) | A2/A3 | medium — extend `hooks.py` walk beyond ntdll |
| 2 | NTUSER.MAN existence/change alert in persistence auditor | A4 | small |
| 3 | Registry rule: `HKCU\Software\Classes\ms-settings\*` creation (UAC bypass probe) | A7 | small |
| 4 | auditd additions: `bpf`/`perf_event_open` syscall key, interpreter-path watches, `/run/systemd`, tmpfiles.d | B1/B2/B4 | small (rules file) |
| 5 | `sshd -T` semantic-hash watchdog | B3 | small |
| 6 | Cross-view /proc-vs-ps consistency check (bind-mount hiding) | B5 | medium |

Items 1–3 close real Windows gaps in THIS EDR; 4–5 are deployable rules for
Linux images; 6 is the honest ceiling-crosser that needs a second vantage
point.

## Sources

- Windows: [Dark Relay — stealth syscalls](https://www.darkrelay.com/post/stealth-syscall-execution-bypass-edr) · [CovertSwarm — EDR bypass timeline](https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques) · [FluxSec — ghost hunting](https://fluxsec.red/edr-syscall-hooking) · [0xdbgman — EDR internals](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/) · [CyberKach — indirect syscalls](https://www.cyberkach.com/blog/indirect-syscalls-heaven-for-hackers-hell-for-defenders) · [Deceptiq — NTUSER.MAN](https://deceptiq.com/blog/ntuser-man-registry-persistence) · [dev.to — kernel callback blind spots](https://dev.to/harsh_hak/edr-blind-spots-kernel-callbacks-5ae7) · [Nextron — registry persistence detection](https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/) · [Elastic — uncommon registry change](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_registry_uncommon)
- Linux: [Synacktiv — LinkPro eBPF rootkit](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis) · [Datadog — eBPF rootkit detection primitives](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/) · [windshock — eBPF backdoor detection framework](https://windshock.github.io/en/post/2025-04-29-ebpf-backdoor-detection-framework/) · [Trend Micro — BPFDoor hidden controller](https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html) · [Rapid7 — BPFDoor sleeper cells](https://www.rapid7.com/blog/post/tr-bpfdoor-telecom-networks-sleeper-cells-threat-research-report/) · [FortiGuard — Symbiote/BPFDoor eBPF filters](https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware) · [Sandfly — eBPF rootkit incident](https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis) · [MITRE S1161 BPFDoor](https://attack.mitre.org/software/S1161/)
