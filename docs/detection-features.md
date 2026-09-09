# CCDC-EDR Detection Capabilities — Complete Reference

Every detection this EDR can raise, the sensor that produces it, what it
means, and how it was verified. Severity in parentheses. Run `python -m edr`
and open http://127.0.0.1:8420.

## Architecture in one paragraph

Sixteen sensor **threads** (one per sensor, so a slow pass can't stretch
fast cadences) feed a normalized event bus; a Sigma-like rule engine plus
sensor-specific logic raise alerts into a triage queue surfaced by the live
console (the original `edr-ui-only` design). Kernel-fed sources: the NT
Kernel Logger ETW session (process events) and the Security audit log
(4688 with command lines, auto-enabled). Everything is pure stdlib Python
plus ctypes — no agent DLL, no driver, no third-party packages.

## Sensors and their detections

### File & signature layer (`signatures.py`, scan on write/launch, 60s)
| Alert | Fires when | Verified |
|---|---|---|
| SIG-REALM-IMIX (critical) | Realm imix config surface: IMIX_CALLBACK_URI/SERVER_PUBKEY/BEACON_ID, eldritch/tavern strings | suite |
| SIG-RUST-IMPLANT (high) | Rust binary + network/crypto markers | suite |
| SIG-MUSL-ELF (medium) | Static musl ELF with implant strings | suite |
| SIG-ELDRITCH-TOME (high) | Realm tome script content | suite |
| SIG-WEBSHELL-PHP (critical) | eval($_POST) class webshells | suite |
| SIG-CS-BEACON / SIG-HAVOC-DEMON (critical) | Cobalt Strike / Havoc static indicators | byte-tested |
| SIG-WATERSHELL (critical) | watershell-cpp fingerprint: status:/run: magic prefixes, /proc/net/arp+route | suite |
| SIG-MINGW (high) | MinGW/g++ build markers — implant build chain on Windows | suite |
| SIG-DOTNET-OFFTOOL (critical) | Rubeus/Seatbelt/SharpHound etc. names, on disk or in memory | suite |
| SIG-AMSI-BYPASS (critical) | amsiInitFailed/AmsiScanBuffer/AmsiUtils patterns — files, memory, or live 4104 script buffers | suite |
| TIME-STOMP (high) | mtime predates unfakeable NTFS creation time by >30 days | suite |
| FILE-WEBROOT-SHELL / FILE-TOME / FILE-IMPLANT-SIG | content dispatch for the above | suite |

Drop-zone scan covers TEMP/APPDATA/PUBLIC/ProgramData/Windows\Temp/inetpub,
depth 6. Launched images from user paths are scanned at process start.

### Memory layer
| Alert | Sensor | Meaning | Verified |
|---|---|---|---|
| MEM-RWX-UNBACKED (critical) | memmap | private executable region with no file mapping — injected shellcode | suite |
| MEM-RWX-NEW (critical) | memmap | executable region appeared between passes — VirtualAlloc effects tracking | suite |
| MEM-PROMOTE (critical) | memmap | RW→RX permission flip — the allocate-write-protect loader pattern, caught at the transition | tranche-8 |
| MEM-HOLLOWED (critical) | memmap | process's own image base is private memory — hollowing artifact | code-reviewed |
| SYSCALL-STUB (critical) | memmap | `syscall` instruction in private memory — direct/indirect syscall stub (HellsGate/SysWhispers) | suite |
| MEM-SIG-* (critical) | memscan | signature packs against committed memory content — finds running implants with no on-disk copy | suite |
| THREAD-UNBACKED (critical) | hooks | Win32 thread start address in private executable memory — CreateRemoteThread artifact | suite |
| THREAD-HIJACK (critical) | hooks | live RIP in private memory — SetThreadContext redirection aftermath | suite |
| STACK-UNBACKED (high) | hooks | stack return address into unbacked memory — injected frames / stack spoofing | code-reviewed |
| NTDLL-TAMPER (critical) | hooks | mapped ntdll .text ≠ on-disk — inline API hooks or EDR unhooking, with patched addresses | suite |
| LSASS-HANDLE (critical) | lsass | any process holding VM_READ/DUP handles to lsass — credential theft prerequisite | suite |
| PROC-XHANDLE (critical) | handles | cross-process VM_WRITE/CREATE_THREAD handle — injection prerequisite posture | live-verified* |

### Process / execution layer (WMI poll + 4688 twins for sub-second events)
| Alert | Meaning | Verified |
|---|---|---|
| PROC-ENC-PS / EVT-4688-SUSP (high) | encoded PowerShell, LOLBIN fetches | suite |
| PROC-MASQ (critical) | critical system binary name outside Windows (svchost.exe in Temp) | suite |
| SPAWN-SHELL (critical) | user-path binary spawned cmd/powershell — passive-backdoor shell spawner | suite |
| PROC-SUSP-PARENT (critical) | real parent-PID matrix: w3wp/sqlservr/Office/spoolsv → interpreter (webshell/macro chain) | suite |
| PROC-DEFENDER-SIDELOAD (critical) | Defender binary outside install path | live |
| EVT-SCRIPTHOST (high) | wscript/cscript/mshta executing drop-zone content | live |
| PROG-IMPLANT-LAUNCH (critical) | launched image hit a signature pack | suite |

### Credential access & tamper
| Alert | Meaning |
|---|---|
| PROC-SAM-SAVE / EVT-SAM-SAVE (critical) | reg save of SAM/SYSTEM/SECURITY hives |
| PROC-MIMIKATZ-CLI (critical) | mimikatz module / LSASS minidump command lines |
| KRB-ROAST (high) | 4769 with RC4 ticket — Kerberoasting (coded; needs DC to exercise) |
| PROC-LOG-CLEAR / EVT-LOG-CLEAR (critical) | wevtutil cl — anti-forensics |
| PROC-AUDIT-DISABLE / EVT-AUDIT-DISABLE (critical) | auditpol disable — blinding the kernel-fed sources |
| TAMPER-DEFENDER (high) | Add-MpPreference exclusion |
| TAMPER-AUDIT (critical) | Security log cleared (1102) |
| SENSOR-WATCHDOG (critical) | sensor loop stalled >60s — sensors killed/blinded |

### Persistence auditor (30s baseline+diff — every location, one mechanism)
Run keys, services (**binary signature-scanned at install**), scheduled tasks
(**action modifications**, not just new tasks), Startup folders, WMI
subscriptions + timers (consumer command lines rule-evaluated), IFEO
debuggers, AppInit_DLLs, COM hijacks, .NET CLR profiler hijack, LSA package
tamper, Active Setup, AppCertDlls, PrintMonitor, screensaver, TimeProvider,
Winlogon Notify, SilentProcessExit, netsh helpers, BITS jobs, PowerShell
profiles, SSH authorized_keys/sshd_config. All alert as `PERS-*`
(critical/high) with artifact path in the alert data.

### Network layer
| Alert | Meaning | Verified |
|---|---|---|
| NET-BEACON (critical) | jitter-tolerant cadence: ≥6 connections at near-constant interval to one peer, actor from writable path | suite |
| DNS-BEACON (critical) | same analysis over the DNS Client channel, keyed on registered domain | suite |
| ICMP-BEACON (high) | periodic ICMP echo pattern from kernel counters (imix ICMP transport) | suite |
| NET-LISTENER (high) | non-service binary listening on non-standard port, non-loopback (tcp_bind) | suite |
| NET-PIPE (critical/high) | C2-named pipes (msagent_/postex_/demon) or new pipes hosted by user-path processes | suite |
| PROC-EGRESS-TOOL / EVT twin (critical) | chisel/ngrok/ligolo/cloudflared/frp — egress tunnels | suite |
| PROC-RMM-TOOL / EVT twin (high) | anydesk/teamviewer/rustdesk — interactive backdoors | suite |
| PROC-PSEXESVC / EVT twin (high) | PsExec lateral movement | rule-tested |
| PROC-WINRM-SESSION (medium) | WinRM remoting — fileless lateral movement | rule-tested |
| PROC-NETSH-FIREWALL / EVT twin (high) | firewall rule tampering | suite |
| NET-DEADDROP / EVT twin (high) | fetches from paste/GitHub dead-drop services | suite |

### Module walk (`modules.py`, Toolhelp32)
| Alert | Meaning | Verified |
|---|---|---|
| MOD-SIDELOAD (critical) | Windows-named DLL outside System32 (version.dll/winmm/mpclient) or user-writable module inside a service process | suite |
| HOOK-DLL (critical) | one module across ≥4 processes from writable paths — SetWindowsHookEx global hook / broadcast injection | suite |

### Linux sensor (`linux_sensor.py`, auto-activates on Linux hosts)
| Alert | Meaning |
|---|---|
| PKT-SOCKET (critical) | process owns a raw PF_PACKET socket — watershell-class implant with no listening port |

### AMSI-equivalent content scanning
PowerShell 4104 script-block buffers — the deobfuscated script at execution —
are signature-scanned (SIG-AMSI-BYPASS and all file packs), matching the view
the AMSI stream would see.

## Response capabilities (Alerts screen buttons)
- **kill** — taskkill after guardrails (refuses the EDR itself, critical
  system processes, protected image paths); every action and refusal logged.
- **block** — Windows Firewall in+out deny for the C2 peer (validated IPs only).
- **quarantine** — vault the file with deny-execute ACL, manifest for
  restore, and **automatic config extraction**: embedded callback URIs are
  pulled and the C2 peer is auto-blocked at the firewall.
- **intel** — OSINT enrichment: offline RFC/infra classification, rDNS,
  RIPEstat whois/ASN/holder/geo; cached 6h; auto-attached to beacon alerts.
- **ack/resolve** triage states; per-rule enable/disable toggles with live
  hit counts; live rule-test panel.

## Console
Five-screen UI (original edr-ui-only design): Dashboard (tiles, ingest
sparkline, sensor health, action buttons with feedback), Log Explorer
(facets + raw record drawer), Alerts (grouped, why-this-fired, beacon
cadence plot, response buttons), Signatures (toggles + live test), Threat
Intel (framework cards with live hit counts, attack-chain stages).

## Test coverage
`tests/run_tests.py` (21 classic), `run_tranche4.py` (11), `run_tranche5.py`
(7), `run_tranche6.py` (4), `run_tranche7.py` (8), `run_tranche8.py` (1) —
all benign simulations, cleaned up after each run. One known flake:
PROC-XHANDLE in tranche-5 (handle-table snapshot race; detector verified
live repeatedly — see implementation report).

## Documented walls (not bugs)
- ETW-TI (THREATINT_ALLOCVM_*) — PPL-signing requirement, attempted every boot.
- Kernel callbacks — needs a signed driver.
- Per-peer ICMP attribution — needs the kernel trace.
- Sleep-encrypted memory — needs wake-transition scanning (injection-based).
