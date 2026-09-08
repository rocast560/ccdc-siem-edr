#!/usr/bin/env bash
# KALI - one-time tooling for the sideloading walkthrough (step 1).
set -e
echo "[*] installing Rust + Windows cross-compile toolchain..."
if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
rustup target add x86_64-pc-windows-gnu
if ! command -v cargo-zigbuild >/dev/null; then
    cargo install cargo-zigbuild
fi
command -v zig >/dev/null || { apt-get update && apt-get install -y zig || pip3 install ziglang; }
apt-get install -y mingw-w64 2>/dev/null || true   # fallback linker
echo "[*] done. verify with:  cargo zigbuild --version  && rustup target list --installed"
