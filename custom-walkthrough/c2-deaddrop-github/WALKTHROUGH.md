# Test: C2 — dead-drop resolver over GitHub Gists (T1102.001)

**The technique (research):** 2025–26 implants increasingly never touch attacker
infrastructure. A **dead-drop resolver** points the implant at a legitimate public service
(a GitHub Gist, a git commit message, a Telegram/Discord API) where the operator updates
the *real* C2 address — so the binary contains no C2 to find, and the traffic goes to
trusted domains no allow-list blocks. Real cases: [Drokbk/Chaes using GitHub](https://www.sophos.com/en-us/blog/drokbk-malware-uses-github-as-dead-drop-resolver),
[C2Looper (2026) over GitHub](https://www.zscaler.com/blogs/security-research/c2looper-new-backdoor-likely-tied-ransomware-github-c2),
[Discord webhook C2 in npm supply chains](https://socket.dev/blog/weaponizing-discord-for-command-and-control),
[Microsoft Graph as C2 (Cycraft 2026)](https://www.cycraft.com/en/post/ddr-apt-en-20260331),
[MITRE T1102.001](https://attack.mitre.org/techniques/T1102/001/).

**The detection to implement later (filed in
`../../development-research/future-detections-research.md`):** `NET-DEADDROP` — a
**non-browser process** connecting to `api.github.com` / `gist.github.com` /
`discord.com/api` / `api.telegram.org` / `graph.microsoft.com`. Your netstat flow sensor
already collects per-process connections; this is one rule over existing telemetry.

**Wiring it to Realm C2 (honest note):** imix has no built-in dead-drop mode — real
deployments put a **redirector** in front of Tavern: the implant's `IMIX_CALLBACK_URI`
points at a small local agent that resolves the *actual* Tavern address by reading a Gist
on each cycle. Operator rotates the Gist instead of rebuilding the implant.

```
imix (IMIX_CALLBACK_URI=http://127.0.0.1:9443)        <- callback baked at build (step b of _common)
        -> local resolver script (this test)           <- polls a Gist for the real address
        -> Tavern on 172.16.69.109:8080                <- real C2, invisible in the binary
```

## Manual test (victim, this machine)

**1. Create the dead drop (any GitHub account):** make a Gist containing one line —
`TAVERN=172.16.69.109:8080` — and note its raw URL
(`https://gist.githubusercontent.com/<you>/<id>/raw`).

**2. Run the resolver as an "implant-grade" process** (the point is the process is NOT a
browser): `.\test.ps1 -GistUrl <raw-url>` polls the Gist every 30s from powershell/python
and, if you have the real implant built, launches `sysupd.exe` (built per
[`../_common/implant-build.md`](../_common/implant-build.md)).

**3. Watch the EDR console while it polls.**

**Expected vs gap:**

| Signal | Today |
|---|---|
| `sysupd.exe` drop/launch/beacon | ✅ full chain (`SIG-*`, `EVT-4688-TEMP`, `PROG-IMPLANT-LAUNCH`, `NET-BEACON`) |
| Non-browser process → `api.github.com`/`gist.githubusercontent.com` every 30s | ❌ GAP — exactly the `NET-DEADDROP` rule this test justifies. The flows are already in your netstat sensor; nothing keys on the destination |
| Implant binary analysis | ✅ nothing to find — the C2 isn't in the binary (that's the attacker's win this test demonstrates) |

**Fix when implemented:** flow sensor enriches per-process records with a dead-drop
endpoint list; any match where the process is not a signed browser → critical. Also cover
the periodicity angle: a 30s-interval poller to a static-content URL is beacon-shaped.

**Cleanup:** stop the poller job; no artifacts.
