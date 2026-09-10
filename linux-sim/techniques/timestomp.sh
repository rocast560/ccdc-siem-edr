# technique: timestamp forgery (guide 5.1) — mtime copied from /etc/passwd,
# ctime (unforgeable) now disagrees
name="timestomp"
plant() {
    echo 'ccdc-sim marker' > /usr/local/share/ccdc-sim-stomped.txt
    touch -r /etc/passwd /usr/local/share/ccdc-sim-stomped.txt
}
clean() {
    rm -f /usr/local/share/ccdc-sim-stomped.txt
}
