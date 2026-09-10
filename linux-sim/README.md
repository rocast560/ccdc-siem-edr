# linux-sim — automated Linux attack simulation for detection testing

Plants marked, benign versions of the persistence/evasion techniques from
`development-research/linux-persistence-evasion-guide.md` at intervals, so you
can score your monitoring (auditd keys, SIEM alerts, baseline diffs) against a
ground-truth log of exactly what happened and when.

**Safety**: every artifact is tagged `ccdc-sim`, nothing touches the network
(no beacons, no outbound connections — payloads are pure sleep loops), and
`cleanup.sh` + `verify.sh` prove the box is back to clean. Run only on
practice images you own (CCDC VMs, WSL, scratch containers). Root required.

## Usage

```bash
cd linux-sim
sudo ./simulate.sh --list                 # show available techniques
sudo ./simulate.sh --all                  # plant one of each, once
sudo ./simulate.sh --interval 120 --count 20   # random technique every 2 min, 20 rounds
sudo ./simulate.sh --only ssh-key,cron-drop    # specific set
sudo ./simulate.sh --all --no-cleanup     # leave artifacts in place for hunting
sudo ./cleanup.sh                         # remove everything
sudo ./verify.sh                          # prove nothing is left behind
```

## Ground truth

Every action appends a JSON line to `actions.log`:

```json
{"ts":"1725900000","iso":"2025-09-09T17:20:00Z","technique":"ssh-key","action":"plant","artifacts":["/root/.ssh/authorized_keys"]}
```

Score yourself: for each `plant`, did your auditd key / SIEM rule / baseline
diff fire? Anything missed is a detection gap — the guide's DETECT sections
tell you what should have caught it.

## Techniques

| script | emulates | guide § |
|---|---|---|
| user-add.sh | UID-0 rogue user + sudoers drop | 1.1 |
| ssh-key.sh | authorized_keys + authorized_keys2 | 1.2 |
| cron-drop.sh | /etc/cron.d + @reboot user crontab | 2.1 |
| systemd-timer.sh | service + timer, enabled | 2.2 |
| udev-rule.sh | udev RUN+= rule | 2.3 |
| ldpreload.sh | /etc/ld.so.preload (harmless .so copy) | 3.1 |
| rc-hijack.sh | .bashrc + /etc/profile.d | 3.2 |
| memfd.sh | memfd_create fileless execution | 4.1 |
| deleted-binary.sh | run-then-delete binary | 4.2 |
| timestomp.sh | touch -r timestamp forgery | 5.1 |
| immutable.sh | chattr +i hostile immutable | 5.2 |
| firewall-off.sh | iptables flush + ufw disable (state saved) | 5.4 |
| hist-off.sh | history/accounting sabotage drop-in | 5.5 |
| at-job.sh | at queue payload (if atd present) | 2.x |

## Detection scoring against THIS repo's EDR

The Windows EDR (`python -m edr`) catches the same technique families on
Windows hosts (SPAWN-SHELL, NET-BEACON, TAMPER-AUDIT, PERS-*, TIME-STOMP,
PROC-MASQ...). `linux-sim` is the Linux-side counterpart: run it on a Linux
practice image with the guide's auditd rules loaded, and ship the audit log
to wherever your SIEM lives.
