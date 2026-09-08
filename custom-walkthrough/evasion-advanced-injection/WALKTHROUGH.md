# Test: Evasion (very advanced) — Mockingjay / module stomping / thread-pool injection

**The techniques (research):** the current loader generation, each defeating a specific
detection layer:

- **Mockingjay** — signed Microsoft DLLs that ship with **default RWX sections**
  (e.g., `sysid.dll` from the Mesa/OpenGL stack): copy shellcode into a section that is
  *already* writable+executable. No `VirtualAlloc`/`VirtualProtect`/remote writes — the
  entire API surface your future hook layer watches simply isn't used
  ([SecurityJoes' original research](https://securityjoes.com/blog/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution-imported),
  [detection guidance](https://nsetshedi-ss.medium.com/detecting-mockingjay-process-injection-2bb50e016aad)).
- **Module stomping / DLL hollowing** — `LoadLibrary` a large legitimate signed DLL, then
  overwrite its `.text` section with shellcode. In-memory the module looks like a valid
  signed library — defeats memory scanners that trust loaded modules
  ([ired.team reference implementation](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection),
  [advanced staging chains](https://infosecwriteups.com/dont-be-so-primitive-evolving-the-module-stomping-staging-chain-59fb96db50ac),
  [naksyn's scanner-evasion analysis](https://naksyn.com/edr%2520evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html)).
- **Thread-pool injection** — `TpAllocWork`/`TpPostWork` execute shellcode via
  thread-pool callbacks: **no thread is ever created**, so CreateRemoteThread-centric
  detection sees nothing ([Tartarus TpAllocInject](https://medium.com/@yua.mikanana19/tartarus-tpallocinject-opsec-safe-loaders-red-team-shellcode-syscall-execution-bypass-8cc263f456ef),
  [r-tec on evading kernel-triggered memory scans](https://www.r-tec.net/r-tec-blog-process-injection-avoiding-kernel-triggered-memory-scans.html)).

All three have public benign PoCs. None are caught by your current sensors *at injection
time*; your surviving detections are the edges (file writes, launch paths, beacon
cadence) — exactly what this test documents.

## Manual test (attacker build -> victim run)

**Mockingjay PoC** ([SecurityJoes' repo / community PoCs](https://securityjoes.com/blog/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution-imported)):
```bash
# build the PoC per the repo; it copies marker shellcode into sysid.dll's RWX .sgi section
# locally, or side-loads a DOCTORED copy of sysid.dll
```
```powershell
# victim: the PoC runs and its proof message boxes / marker appears
.\mockingjay.exe     # benign PoC: execution with zero Virtual* calls
```

**Module stomping** (e.g., public C# PoCs targeting a large signed DLL such as
`System.Drawing.ni.dll` or `msvcp140.dll`):
```powershell
.\stomping.exe       # loads legit DLL -> overwrites .text with marker shellcode -> runs it
```

**Thread-pool injection** (Tartarus-style PoCs):
```powershell
.\tpinject.exe       # TpAllocWork callback executes marker shellcode; no new thread in the process
```

For a **Realm-integrated variant**: replace each PoC's marker shellcode with a loader
that spawns `sysupd.exe` (built via [`../_common/implant-build.md`](_common/implant-build.md))
— then the surviving detection chain (`SIG-*` on the spawned file, `EVT-4688-TEMP`,
`PROG-IMPLANT-LAUNCH`, `NET-BEACON`) can be observed end-to-end through the injection.

**Expected vs gap:**

| Signal | Today | With Sysmon | With your future memory scanner |
|---|---|---|---|
| The injection act itself | ❌ invisible | ⚠️ EID 8/10 for some variants; TpAllocWork partially | stomping defeats naive scanners — **must** hash-compare loaded modules against on-disk files (see future-detections-research.md design note) |
| Spawned implant file + launch | ✅ full chain | ✅ | ✅ |
| Beacon cadence | ✅ | ✅ | ✅ |

**The lesson for your roadmap:** when you build the memory scanner
(research-guide §4 item 3), module stomping is the adversary it must be designed
against: never trust "this region belongs to a signed module" — re-hash the on-disk file
and compare. Mockingjay is the argument for flagging *any* default-RWX section with
non-zero entropy, and TpAllocWork is the argument for scanning thread-pool callback
targets, not just thread start addresses.

**Cleanup:** delete PoC binaries; kill spawned implant processes.
