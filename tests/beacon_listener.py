"""Loopback sink for the fake implant's beacon (so flows show ESTABLISHED)."""
import socket, time

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9101))
srv.listen(16)
while True:
    c, _ = srv.accept()
    try:
        c.recv(64)
        c.sendall(b"ok")
        time.sleep(6)          # hold the session so both sides stay ESTABLISHED
    except OSError:
        pass
    c.close()
