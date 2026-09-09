# How Commercial EDRs Work — Technique Research & Gap Analysis

Research for: closing the gap between this CCDC practice EDR and the detection
engineering used by CrowdStrike Falcon, SentinelOne Singularity, and Microsoft
Defender for Endpoint. All sources are publicly accessible vendor documentation
and engineering blogs (linked inline).

---

## 1. CrowdStrike Falcon

**Architecture** ([Tech Analysis: CrowdStrike's Kernel Access and Security Architecture](https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/),
[Falcon Insight data sheet](https://www.crowdstrike.com/wp-content/uploads/2022/03/crowdstrike-falcon-insight-data-sheet.pdf)):

- **Kernel driver + user-mode service split.** The driver uses *documented*
  Microsoft extension points, not hooks: filter-manager callbacks (file system),
  registry filtering, process-creation and object callbacks, thread-creation
  notifications, image-signature verification callbacks, named-pipe filtering.
  Deliberately avoids syscall hooking / kernel patching.
- **ELAM early-boot** validation of the boot chain before user-mode services run
  (bootkit/rootkit/firmware coverage).
- **User-mode ML engine runs in a PPL (Protected Process Light) sandbox** with
  AppContainer least-privilege — tamper-resistant even against SYSTEM.
- Consumes **Secure ETW, the Threat-Intel ETW channel, and AMSI** rather than
  shipping its own script/macro parsers.
- **Cloud-side correlation (Threat Graph):** the sensor streams high-fidelity
  behavioral telemetry; heavy ML, reputation, and cross-enterprise graph
  analytics happen in the cloud.

**Detection philosophy — IOA over IOC:** detections target *sequences of
behavior* (Indicators of Attack: injection, credential dumping, lateral
movement) rather than only static artifacts, which is what makes fileless and
zero-day tradecraft visible. Behavioral analytics profile normal-vs-anomalous
activity ([CrowdStrike behavioral analytics](https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/behavioral-analytics/)).

## 2. SentinelOne Singularity

**Architecture** ([The Behavioral AI Engine](https://www.sentinelone.com/blog/decrypting-sentinelone-detection-the-behavioral-ai-engine-in-real-time-cwpp/),
[Behavioral AI — an unbounded approach](https://www.sentinelone.com/blog/behavioral-ai-an-unbounded-approach-to-protecting-the-enterprise/)):

- **Two model families:** *Static AI* (pre-execution ML on the file itself) and
  *Behavioral AI* (post-execution, watching kernel-level process/thread actions
  and memory usage in real time). Models run **locally on the agent** — no
  cloud round-trip for a verdict.
- **Storyline™ causality graph:** every process/file/network/registry event on
  the host is correlated into parent→child causal chains; the analyst sees one
  *story* per incident, not hundreds of atomic alerts. One alert per storyline.
- **Probabilistic thresholds of normalcy** per thread; crossing them triggers
  machine-speed protection.
- **Detect vs Protect modes:** moderate-confidence findings alert only;
  high-confidence findings trigger policy-governed automatic remediation.
- **Response semantics:** one-click kill terminates *the entire threat sequence*
  (process tree, not just one PID); quarantine encrypts the threat file; network
  containment cuts egress.

## 3. Microsoft Defender for Endpoint

**Architecture** ([Advanced technologies in Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav),
[Behavioral blocking & containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment),
[ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)):

- **Endpoint behavioral sensors** + cloud security analytics + threat intel in
  layers: next-gen protection, attack-surface-reduction rules, behavioral
  blocking and containment, automated investigation.
- **Block-at-first-sight:** cloud-delivered protection makes block/allow
  decisions on new unknown files within seconds.
- **ASR rules** harden common vectors proactively (Office child processes,
  PSExec/WMI process creation, unsigned drivers...).
- **Device isolation:** full network containment of an endpoint while the
  management channel stays reachable — the flagship "stop C2 traffic without
  touching the box" response.

---

## 4. Cross-cutting advanced techniques (what actually separates products)

1. **Correlated verdicts instead of atomic alerts.** All three fuse many weak
   signals into one scored entity/incident with a confidence level. Atomic
   alerts are telemetry; the *verdict* is the product.
2. **Process causality.** Parent/child chains preserved across events so the
   analyst (and the response engine) can act on the root of the tree.
3. **Tiered response semantics** — monitor / contain-preserving-evidence /
   cut-egress-only / terminate-tree / isolate-host — each with guardrails and an
   audit trail, plus **verification that containment actually worked**.
4. **Detect-vs-Protect policy** (manual triage vs automatic remediation at a
   confidence threshold).
5. **Tamper protection** for the sensor itself (PPL/kernel enforcement).
6. **Cloud reputation and first-sight verdicts** on unknown binaries/peers.

## 5. Gap analysis vs this EDR (before this build)

| Commercial technique | Our status before | Ceiling in user-mode Python |
|---|---|---|
| Kernel callbacks (proc/thread/reg/file filters) | Approximated: WMI poll, ETW, eventlog, VirtualQueryEx walks | No driver; ETW + polling is our ceiling (documented in report addenda) |
| ETW + AMSI consumption | Have (.NET loader ETW, AMSI-bypass signature, 4104) | Done |
| Atomic behavioral detections (IOA-style rules) | ~46 rules + 12 signature packs | Done |
| **Signal fusion → one scored verdict per entity** | **Missing — alerts only** | Fully buildable userland |
| **Storyline causality (parent→child)** | Partial (suspicious-parent matrix, no graph) | Buildable (we track parentage in events) |
| **Tiered response + containment verification** | Partial (kill/suspend/block exist; no entity-level quarantine, no verify) | Fully buildable |
| **Tree kill (whole threat sequence)** | Missing (single PID only) | Buildable (`taskkill /T`) |
| **Device/network isolation** | Missing | Buildable (firewall block-all-outbound; loopback exempt keeps console alive) |
| Detect-vs-Protect auto policy | Missing | Buildable (auto-quarantine ≥ threshold) |
| Tamper protection (PPL) | Guardrails only (refuse self-kill; watchdog) | Cannot sign PPL — documented ceiling |
| Cloud reputation / first-sight | OSINT enrichment (RIPEstat) | Have an open-source version |
| ML static+behavioral models | Weighted-evidence heuristics only | ML training out of scope; scoring engine substitutes |

## 6. What this build adds as a result

1. **`edr/correlation.py` — implant confidence engine.** Fuses every alert
   into per-entity evidence bundles (entity = binary path, or pid, or C2 peer)
   with per-rule weights, producing a 0–99 confidence score and tier
   (suspicious / likely / confirmed). This is our Storyline-equivalent verdict
   layer, and it feeds the new Implants screen.
2. **Entity-level quarantine with verification.** `quarantine_entity` performs
   the full containment sequence: block C2 peers at the firewall → terminate
   the process *tree* → vault the binary (config extraction auto-blocks
   extracted peers) → record status. `verify_containment` re-checks liveness,
   peer silence, and firewall rules, and the UI shows an explicit
   **QUARANTINED / inactive** state only after checks pass.
3. **Host isolation.** One-click network containment (block all outbound,
   loopback exempt so the console stays reachable) with release.
4. **Detect-vs-Protect policy.** Optional auto-quarantine when confidence
   crosses the confirmed threshold (default off — manual triage).
5. **Implants screen (7th console section).** The dedicated "things we are
   ~99% sure are implants" view with status lifecycle
   (active → suspended/quarantined/killed → verified-inactive) and the full
   response toolkit per implant.
6. **Console-wide button interactivity audit** — every rendered button is
   clickable, animated, and bound to real behavior.

## 7. Deliberately out of scope (userland ceiling)

Kernel drivers/ELAM, PPL signing, cloud ML training pipelines, HVCI policy.
These require signing certificates and Microsoft certification programs —
documented here as the hard ceiling for a practice rig, with the userland
approximations noted in the implementation report addenda.

## Sources

- CrowdStrike — [Kernel access & security architecture](https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/), [Falcon Insight data sheet](https://www.crowdstrike.com/wp-content/uploads/2022/03/crowdstrike-falcon-insight-data-sheet.pdf), [behavioral analytics](https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/behavioral-analytics/), [endpoint security platform](https://www.crowdstrike.com/en-us/platform/endpoint-security/)
- SentinelOne — [Behavioral AI engine](https://www.sentinelone.com/blog/decrypting-sentinelone-detection-the-behavioral-ai-engine-in-real-time-cwpp/), [Behavioral AI approach](https://www.sentinelone.com/blog/behavioral-ai-an-unbounded-approach-to-protecting-the-enterprise/), [SentinelOne EDR overview (Cynet)](https://www.cynet.com/security-foundations/endpoint-security/understanding-sentinelone-edr/)
- Microsoft — [Defender AV advanced technologies](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav), [behavioral blocking & containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment), [ASR rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
