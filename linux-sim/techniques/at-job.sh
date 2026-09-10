# technique: at-queue payload (guide 2.x)
name="at-job"
plant() {
    command -v at >/dev/null || { echo "atd missing - skipping"; return 1; }
    echo '/usr/local/bin/ccdc-sim-beacon' | at now + 1 minute 2>/dev/null
    echo '/usr/local/bin/ccdc-sim-beacon' | at now + 5 minutes 2>/dev/null
}
clean() {
    for j in $(atq 2>/dev/null | awk '{print $1}'); do
        if at -c "$j" 2>/dev/null | grep -q ccdc-sim; then atrm "$j"; fi
    done
}
