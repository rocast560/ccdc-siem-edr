# taunts — harmless post-access pranks (CCDC red-team classics)

The competition tradition: once the red team has (sanctioned) access, prove
it without doing damage — change the wallpaper, open a browser tab, put an
image on screen. These scripts automate exactly that tier of taunt, in this
repo's safety idiom.

**Scope**: run only on competition/practice images you are authorized to
touch (that is the whole point of the tradition — a visible, harmless
"we're in" instead of destruction). Every effect is reversible: originals
are saved before change, spawned windows are tracked for undo, and a ledger
records what happened. Nothing here deletes, disables, or persists beyond
an optional interval task you can list and remove with one command.

**Detection angle (the blue-team half)**: each taunt's *delivery* uses the
persistence shapes documented in `development-research/` (scheduled tasks,
registry, systemd timers). If the blue team's monitoring is working, the
taunt never even lands — the task creation fires `PERS-TASK` / auditd
`systemd` keys first. Funny for red, useful for blue.

## Windows (admin PowerShell)

```powershell
cd taunts\windows
.\wt1-wallpaper.ps1                       # swap wallpaper (original saved)
.\wt2-browser-storm.ps1                   # staggered tabs, default = rickroll
.\wt3-image-spam.ps1                      # multiplying picture popups
.\wundo.ps1                               # restore everything
.\wt1-wallpaper.ps1 -IntervalMin 5        # on a timer via scheduled task
                                          # (detection: PERS-TASK should fire)
```

## Linux (root or the session user)

```bash
cd taunts/linux
sudo ./lt1-wallpaper.sh /path/to/image.png   # gnome/kde/xfce auto-detect
sudo ./lt2-browser-storm.sh                  # xdg-open tab storm
sudo ./lt3-image-spam.sh                     # feh/eog popup storm
sudo ./lundo.sh
```

## Ledger

`taunts/taunt-ledger.jsonl` records every action (what changed, where the
original was saved, which PIDs were spawned) — the undo script reads it.

## Editing

Every script has a CONFIG block (counts, delays, URLs, image paths). Swap
the wallpaper image, the video URL, and the popup count to taste. Keep the
contract: harmless effects, originals saved, undo works.
