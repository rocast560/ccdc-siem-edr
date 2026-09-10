#!/bin/bash
# lundo.sh -- undo every Linux taunt: wallpaper back, viewers closed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SAVED="$HERE/.orig-wallpaper"

# wallpaper back
if [ -f "$SAVED" ]; then
    ORIG="$(cat "$SAVED")"
    case "$XDG_CURRENT_DESKTOP" in
        *GNOME*)  gsettings set org.gnome.desktop.background picture-uri "$ORIG" 2>/dev/null
                  gsettings set org.gnome.desktop.background picture-uri-dark "$ORIG" 2>/dev/null ;;
        *XFCE*)   xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s "${ORIG//\'/}" 2>/dev/null ;;
        *)        echo "restore manually: $ORIG" ;;
    esac
    rm -f "$SAVED"
    echo "wallpaper restored"
fi

# viewers + tabs this kit spawned
pkill -f 'ccdc-taunt' 2>/dev/null
for v in feh eog mirage; do pkill -x "$v" 2>/dev/null && echo "closed $v windows"; done
echo "== taunts undone."
