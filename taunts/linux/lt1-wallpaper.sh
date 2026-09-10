#!/bin/bash
# lt1-wallpaper.sh -- swap the wallpaper (gnome/kde/xfce/mate auto-detect).
# The original is saved next to the script for lundo.sh.
# usage: lt1-wallpaper.sh [/path/to/image.png]   (generates one if omitted)
set -u
IMG="${1:-/tmp/ccdc-taunt.png}"
SAVED="$(dirname "$0")/.orig-wallpaper"
LEDGER="$(dirname "$0")/../taunt-ledger.jsonl"

# generate a taunt image if none supplied
if [ ! -f "$IMG" ]; then
    command -v convert >/dev/null && convert -size 1920x1080 xc:'#10141a' \
        -pointsize 96 -fill orange -gravity center \
        -annotate +0+0 'CCDC RED TEAM WAS HERE' "$IMG" && :
    [ -f "$IMG" ] || { printf 'P1\n80 1\n' > /dev/null; echo "no imagemagick - supply an image path"; exit 1; }
fi

save_original() {
    case "$XDG_CURRENT_DESKTOP" in
        *GNOME*)  gsettings get org.gnome.desktop.background picture-uri-dark 2>/dev/null \
                     || gsettings get org.gnome.desktop.background picture-uri ;;
        *KDE*)    grep -h WallpaperPlugin "$HOME/.config/plasma-org.kde.plasma.desktop-appletsrc" 2>/dev/null | head -1 ;;
        *XFCE*)   xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image 2>/dev/null ;;
        *)        echo unknown ;;
    esac
}
ORIG="$(save_original)"
printf '%s\n' "$ORIG" > "$SAVED"

case "$XDG_CURRENT_DESKTOP" in
    *GNOME*)
        URI="file://$(readlink -f "$IMG")"
        gsettings set org.gnome.desktop.background picture-uri "$URI"
        gsettings set org.gnome.desktop.background picture-uri-dark "$URI" 2>/dev/null
        ;;
    *KDE*)    plasma-apply-wallpaper-image "$IMG" 2>/dev/null || \
              qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript \
              "wallpaperForOutput outputs()[0].currentConfigGroup[0].Image='$IMG'" ;;
    *XFCE*)   xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s "$IMG" ;;
    *)        echo "unknown desktop ($XDG_CURRENT_DESKTOP) - set manually: $IMG" ;;
esac

printf '{"ts":"%s","playbook":"ccdc-taunt","step":"wallpaper-set","detail":"%s","original":"%s"}\n' \
    "$(date +%s)" "$IMG" "$ORIG" >> "$LEDGER"
echo "== wallpaper set (original saved). undo: sudo ./lundo.sh"
