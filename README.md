# ccdc-siem-edr - UI + working sensor backend

Interface for a CCDC-style blue-team EDR/SIEM console, plus the Python sensor
backend that feeds it live telemetry on Windows. Pure stdlib - no third-party
packages, no agent install, run as Administrator.

## Run the EDR

```
python -m edr              # console + sensors at http://127.0.0.1:8420
python tests/run_tests.py  # benign live-fire payload suite (separate shell)
```

The backend serves a fully live five-screen console (`edr/live_console.html`) — every
number, row, chart, and rule toggle is wired to the sensor API; there is no sample data:

- **Dashboard** — severity tiles, ingest sparkline, sensor status, one-click
  audit/scan/re-baseline actions
- **Log Explorer** — faceted filters with proportional count bars, search, detail drawer
- **Alerts** — grouped by rule, ack/resolve triage, "why this fired" panel, beacon cadence plot
- **Signatures** — rule toggles with live hit counts, live rule-test panel, signature pack hits
- **Threat Intel** — framework indicator cards (Havoc/CS/Mythic/Realm) with live hit counts,
  stage-by-stage attack chain

API:

- `GET /api/state` - events, alerts, scans, stats, rules
- `GET /api/rules`, `GET /api/scans`
- `POST /api/baseline` (re-arm the persistence T0 baseline), `POST /api/scan`,
  `POST /api/audit` (force a persistence diff now)

### Sensors

| Sensor | What it does |
| --- | --- |
| ETW kernel trace | Starts the reserved NT Kernel Logger session (process events) -> `edr/state/kernel.etl` for forensics |
| Windows event channels | Security 4688 (cmd lines, auditing auto-enabled), 4698/4702/4720/1102, System 7045/7040, PowerShell 4104, Sysmon if present |
| Process poll | WMI Win32_Process with full command lines; on-launch signature scan of images from user-writable paths |
| Persistence auditor | Run keys, services, tasks, Startup folders, WMI subscriptions, IFEO/AppInit - baseline + 30s diff |
| Signature scanner | YARA-style byte rules (Realm imix, Rust implants, musl ELF, eldritch tomes, webshells, CS/Havoc) on write/launch in drop zones (`edr/signatures.py`) |
| Beacon cadence | netstat flow table; jitter-tolerant periodicity analysis per (pid, peer) |

The "YARA rules" live in `edr/signatures.py`; detection rules (Sigma-like,
with why-this-fired text) live in `edr/rules.py`. Runtime state (baseline,
eventlog bookmarks, kernel.etl) is written to `edr/state/` and gitignored.

Test payload research and the implementation/test reports are in
`development-research/`.

## Run it

Open `ccdc-edr-console.html` in a browser. No server, no build step, no
dependencies, no network requests.

The five navbar tabs switch screens. The **Interface system** button in the
bottom-right corner opens the token and component sheet.

## What is here

| File | What it is |
| --- | --- |
| `ccdc-edr-console.html` | The console. All five screens plus the interface system sheet, in one self-contained file. |
| `Main.dc.html` | Dashboard artboard |
| `LogExplorer.dc.html` | Log Explorer artboard |
| `Alerts.dc.html` | Alerts triage artboard |
| `Rules.dc.html` | Signatures / rules manager artboard |
| `Intel.dc.html` | Threat Intel and attack-chain artboard |
| `DesignSystem.dc.html` | Tokens, type ramp, components |
| `canvas.json` | Artboard layout manifest |

The `.dc.html` artboards are the per-screen sources. Each also renders standalone
in a browser.

## Screens

1. **Dashboard** - severity counts, ingest volume against the intrusion window,
   correlated kill chain in the right rail.
2. **Log Explorer** - faceted filters with proportional count bars, a virtualized
   26px-row table, and a detail drawer showing the normalized record above the raw one.
3. **Alerts** - grouped by rule, with a "why this fired" panel that prints the matched
   selection per stage, and a beacon-cadence plot showing the periodicity the rule keyed on.
4. **Signatures** - pack tabs, togglable rules with live hit counts, a form beside the
   raw Sigma-like JSON, and a live-test panel.
5. **Threat Intel** - framework indicator cards that each end in an ATT&CK ID, an Event ID,
   and the rule that fires on it, plus a stage-by-stage attack chain.

## Design basis

Dark tokens come from [Blueprint](https://blueprintjs.com/), Palantir's open-source
design system: surfaces `#111418` through `#404854`, 2px radius, 24/26px controls,
the intent ramp. The screen architecture is the dense analyst-console idiom -
navbar, context toolbar, up to three work regions, status bar. No proprietary
product UI is reproduced.

The severity ramp is a reserved status scale, re-stepped until the worst adjacent
pair cleared colour-vision separation (minimum deltaE 11.4). It always ships with a
word or a rule ID beside the swatch, and stacked segments carry a 2px gap, so
severity ordering never depends on colour alone.

## Status

Static hi-fi. Every screen is drawn in a live state with realistic sample data so
the density is honest, but the tables, filters, rule toggles and live-test results
are **not wired**. Building those is the `js/*.js` work from the project plan.

The resource meter in the bottom-right reports this page's own JS heap
(Chrome/Edge only), DOM node count, and main-thread lag measured as timer drift.
A browser cannot read system CPU or RAM; nothing here claims to.

## Scope

Defensive detection-engineering practice material. Every framework indicator is
recorded as an observable artifact mapped to a detection rule. No offensive
tooling, no exploit code, and all telemetry shown is invented sample data.
