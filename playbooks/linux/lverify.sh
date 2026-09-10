#!/bin/bash
# lverify.sh -- proves no Linux playbook artifact survives cleanup.
set -u
FAIL=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "  PASS  $1"; else echo "  FAIL  $1  <-- leftover!"; FAIL=1; fi; }

echo "== lverify"
chk "no user-scope pb unit"     '[ -z "$(ls /root/.config/systemd/user/ccdc-pb1.service /home/*/.config/systemd/user/ccdc-pb1.service 2>/dev/null)" ]'
chk "no service-account cron"   '! crontab -u messagebus -l 2>/dev/null | grep -q ccdc-pb'
chk "no root pb cron"           '! crontab -l 2>/dev/null | grep -q ccdc-pb'
chk "no rc backdoor lines"      '! grep -rq ccdc-pb /root/.bashrc /home/*/.bashrc 2>/dev/null'
chk "no unlinked payload"       '[ -z "$(ls -l /proc/*/exe 2>/dev/null | grep "\.last\|\.locale")" ]'
chk "no tmpfs blobs/loaders"    '[ -z "$(ls /dev/shm/.X11-lock-* /dev/shm/.x-shm-* 2>/dev/null)" ]'
chk "no key stash"              '[ ! -e /etc/.python_history ]'
chk "no dummy service"          '[ ! -e /etc/systemd/system/ccdc-simsvc.service ]'
chk "no sabotage timer"         '[ ! -e /etc/systemd/system/ccdc-pb3.timer ]'
chk "no sabotage loop"          '[ ! -e /usr/local/sbin/.lc-maint ]'
chk "no stage dir"              '[ ! -e /usr/local/share/.cache ]'
chk "no run pids"               '[ -z "$(ls /run/ccdc-pb* 2>/dev/null)" ]'
chk "no implant processes"      '! pgrep -f "X11-lock|x-shm|lc-maint|sleep_crypt"'

if [ "$FAIL" -eq 0 ]; then echo "== CLEAN: no playbook artifacts remain"; else echo "== DIRTY: fix the FAILs above"; fi
exit $FAIL
