# Advanced playbooks — stealth persistence, sleep-cryption, interval sabotage

Editable red-team playbooks for stressing the EDR harder than the marked,
easy-to-find simulations in `tests/` and `linux-sim/`. Each playbook is a
script with a **CONFIG block at the top you can edit** and numbered steps in
the body, so you can reorder, disable, or extend individual stages.

## The safety contract (why these can exist in a defensive repo)

The techniques are real enough to stress detection — encrypted-at-rest
config, in-memory sleep encryption, low-visibility persistence locations,
interval sabotage — but every playbook keeps the purple-team harness:

1. **No command channel.** The implants beacon to **loopback only** and carry
   no execute/relay capability. Their "payload" is presence + cadence.
2. **Sabotage is guarded.** Service-sabotage playbooks create their own dummy
   service and refuse to touch a critical-services blocklist. The exercise is
   *detecting* the stop/start storm, not destroying a real box.
3. **Ground truth is ledgered.** Every artifact path, key, task, and process
   ID is appended to `playbooks/ledger.jsonl` at plant time — that is your
   scoring key and your map for manual cleanup if a script dies mid-run.
4. **Cleanup + verify ship with every set.**
5. **One documented ceiling:** real implants sleep-encrypt via timer-ROP
   (Ekko/Cronos/Foliage — see the technique notes below). Shipping ROP chains
   is out of scope for this repo; our implant does thread-driven
   RW↔RWX flips + XOR stream encryption, which is enough to exercise the
   EDR's memory-transition and scan layers honestly.

## Technique notes (what each playbook exercises)

- **Sleep encryption** — decrypt in memory on wake, re-encrypt before sleep,
  empty the working set so nothing plaintext pages out. Sources:
  [Binary Defense — Understanding Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation),
  [Cronos PoC](https://github.com/Idov31/Cronos),
  [Foliage walkthrough](https://oblivion-malware.xyz/posts/sleep-obf-foliage/),
  [Ekko breakdown](https://dtsec.us/2023-04-24-Sleep/).
  What should still catch it: RW→RWX/RX **permission flips** (our
  MEM-PROMOTE / MEM-RWX-NEW), unbacked private exec pages, thread start
  addresses in private memory, and the **beacon cadence** the encryption
  cannot hide (the process still talks periodically).
- **COM hijack persistence** — HKCU `Software\Classes\CLSID\{...}`
  shadowing HKLM-registered objects, `InprocServer32` pointing into a
  user-writable path. Hunting: baseline CLSIDs, alert on *new* HKCU
  InprocServer32 entries ([Elastic COM hunting](https://www.elastic.co/blog/how-hunt-detecting-persistence-evasion-com),
  [SpecterOps — Revisiting COM Hijacking](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/),
  [Bohops — COM registry abuse](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)).
  Our persistence auditor walks COM locations (`PERS-COM`).
- **WMI event subscriptions** — `__EventFilter` + `CommandLineEventConsumer`
  + binding, timer-triggered. Detection: Sysmon EID 19/20/21, WMI-Activity
  5857+ ([hunting guide](https://detect.fyi/hunting-wmi-event-subscription-persistence-f087900029f4)).
  Ours: `PERS-WMI-SUB`.
- **Interval sabotage** — scheduled task that stops a (dummy) service on a
  jittered interval, then restores later. The detection target is the
  service-control storm (7036/7045-side telemetry) and the task's action
  hash changing (`PERS-TASK`).

## Playbooks

| playbook | OS | does |
|---|---|---|
| `windows/wb1-stealth-persist.ps1` | win | COM hijack + WMI subscription + randomized-name task |
| `windows/wb2-sleep-crypt.ps1` | win | deploys `sleep_crypt_implant.py` (encrypted config, sleep-crypted memory) |
| `windows/wb3-service-sabotage.ps1` | win | dummy service + interval stop/start storm (guarded) |
| `linux/lb1-stealth-persist.sh` | lin | user-scope systemd + cron + rc + unlinked binary |
| `linux/lb2-sleep-crypt.sh` | lin | deploys the same implant on Linux |
| `linux/lb3-service-sabotage.sh` | lin | dummy systemd service + timer storm (guarded) |

Run (Windows, admin PowerShell — use a *copied* interpreter so the EDR's
trusted-image suppression doesn't hide your test, see `tests/bin/`):

```powershell
cd playbooks\windows
.\wb2-sleep-crypt.ps1                 # follow steps; ledger.jsonl gets ground truth
..\wverify.ps1                        # what's planted right now
.\wcleanup.ps1                        # remove everything + verify
```

Run (Linux, root):

```bash
cd playbooks/linux
sudo ./lb1-stealth-persist.sh
sudo ./lcleanup.sh && sudo ./lverify.sh
```

## Scoring

```bash
jq -r '.artifact' ../ledger.jsonl | sort -u      # everything that exists
```

For each ledger line: did the EDR console (`http://127.0.0.1:8420`) or your
Linux auditd keys fire? The **Implants screen** should fuse sleep-crypt
implants into a confirmed entity (beacon cadence + unbacked RWX + stubs +
permission flips). A stealth-persist artifact that never fires = a coverage
gap; write the rule, re-run, watch it close.

## Editing your own

Copy a playbook, rename with your initials, edit the CONFIG block (names,
intervals, CLSID, paths), add steps as numbered comment blocks. Keep the
contract: loopback only, guarded sabotage, ledger every artifact, cleanup
that can remove what you added.

## Further techniques (research backlog)

`development-research/advanced-evasion-persistence-methods.md` catalogs the
tier above these playbooks with detection mappings: indirect syscalls and
ghost-hunting, module stomping, ETW/AMSI in-process patching, NTUSER.MAN
callback-free registry persistence, callback/fiber execution, herpaderping,
UAC auto-elevate probes (Windows); the BPFDoor/eBPF passive-backdoor family,
interpreter and package-manager persistence, sshd semantic tampering,
systemd generators/tmpfiles.d, bind-mount hiding, initramfs (Linux). It ends
with a six-item detection-upgrade shortlist ranked by effort.
