# technique: /etc/ld.so.preload hijack (guide 3.1) — safe variant: preload a
# COPY of a real library so every binary still works; the FILE + line are the
# detectable artifact
name="ldpreload"
plant() {
    src=""
    for c in /lib/x86_64-linux-gnu/libpcap.so.* /usr/lib/x86_64-linux-gnu/libpcap.so.* \
             /lib/x86_64-linux-gnu/libresolv.so.2 /lib/x86_64-linux-gnu/librt.so.1; do
        [ -e "$c" ] && src="$c" && break
    done
    [ -z "$src" ] && echo "no harmless .so found to copy - skipping" && return 1
    cp "$src" /usr/local/lib/ccdc-sim.so 2>/dev/null || { mkdir -p /usr/local/lib && cp "$src" /usr/local/lib/ccdc-sim.so; }
    echo '/usr/local/lib/ccdc-sim.so' > /etc/ld.so.preload
}
clean() {
    rm -f /etc/ld.so.preload /usr/local/lib/ccdc-sim.so
}
