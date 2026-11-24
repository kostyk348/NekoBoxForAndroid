# Сервер-испытатель: 40% соединений рвёт сразу, остальные отвечают байтом.
import socket, threading, random
random.seed()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9998)); srv.listen(64)
def handle(c):
    try:
        c.settimeout(2)
        if random.random() < 0.4:
            c.close(); return
        c.send(b"R")
        try: c.recv(1024)
        except Exception: pass
        c.close()
    except Exception:
        try: c.close()
        except Exception: pass
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, daemon=True).start()
