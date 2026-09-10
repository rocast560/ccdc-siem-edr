#!/bin/bash
# linux-sim verify — proves no simulation artifact survives cleanup.
# Each check prints PASS/FAIL; any FAIL means leftover artifacts.
set -u
FAIL=0
chk() { # name, command-that-succeeds-when-clean
    if eval "$2" >/dev/null 2>&1; then
        echo "  PASS  $1"
    else
        echo "  FAIL  $1  <-- leftover artifact!"
        FAIL=1
    fi
}

echo "== linux-sim verification"
chk "no ccdc-sim user"            '! grep -q "^ccdc-sim:" /etc/passwd'
chk "no UID-0 non-root user"      '! awk -F: "(\$3==0)&&(\$1!=\"root\"||\$1!=\"toor\")" /etc/passwd | grep -v "^root"'
chk "no sudoers drop"             '[ -z "$(ls /etc/sudoers.d/ccdc-sim 2>/dev/null)" ]'
chk "no ssh key lines"            '! grep -rq ccdc-sim /root/.ssh /home/*/.ssh 2>/dev/null'
chk "no cron artifacts"           '[ -z "$(grep -rl ccdc-sim /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron 2>/dev/null)" ]'
chk "no crontab entries"          '! crontab -l 2>/dev/null | grep -q ccdc-sim'
chk "no systemd units"            '[ -z "$(ls /etc/systemd/system/ccdc-sim.* 2>/dev/null)" ]'
chk "no udev rule"                '[ -z "$(grep -l ccdc-sim /etc/udev/rules.d/*.rules 2>/dev/null)" ]'
chk "no ld.so.preload entry"      '! grep -q ccdc-sim /etc/ld.so.preload 2>/dev/null'
chk "no ld.so.preload file"       '[ ! -e /etc/ld.so.preload ]'
chk "no profile.d hijack"         '[ -z "$(grep -l ccdc-sim /etc/profile.d/*.sh 2>/dev/null)" ]'
chk "no bashrc line"              '! grep -q ccdc-sim /root/.bashrc 2>/dev/null'
chk "no memfd processes"          '[ -z "$(ls -l /proc/*/exe 2>/dev/null | grep "memfd:ccdc-sim")" ]'
chk "no deleted-binary procs"     '[ -z "$(ls -l /proc/*/exe 2>/dev/null | grep "ccdc-sim-hidden")" ]'
chk "no beacon binary"            '[ ! -e /usr/local/bin/ccdc-sim-beacon ]'
chk "no beacon processes"         '! pgrep -f ccdc-sim-beacon'
chk "no stomped marker file"      '[ ! -e /usr/local/share/ccdc-sim-stomped.txt ]'
chk "no immutable artifact"       '[ ! -e /etc/cron.blocked-ccdc-sim ]'
chk "no at jobs"                  '! atq 2>/dev/null | while read -r j _; do at -c "$j" 2>/dev/null; done | grep -q ccdc-sim'
chk "no run-state files"          '[ -z "$(ls /run/ccdc-sim-* 2>/dev/null)" ]'
chk "firewall restored (INPUT policy)" 'iptables -S INPUT 2>/dev/null | head -1 | grep -qvE "ACCEPT *$" || iptables -S 2>/dev/null | grep -q "\-P INPUT DROP\|\-P INPUT REJECT\|-A INPUT.*DROP\|-A INPUT.*REJECT"'

if [ "$FAIL" -eq 0 ]; then
    echo "== CLEAN: no simulation artifacts remain"
else
    echo "== DIRTY: fix the FAILs above (remember chattr -i for immutable files)"
fi
exit $FAIL
