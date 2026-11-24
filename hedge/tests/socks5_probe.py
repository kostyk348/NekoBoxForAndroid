# SOCKS5-клиент: приветствие, CONNECT, приём первого байта сервера.
import socket, struct, sys
def probe(proxy, target, timeout=10):
    s = socket.socket(); s.settimeout(timeout)
    s.connect(proxy)
    s.send(b"\x05\x01\x00"); g = s.recv(2)
    assert g == b"\x05\x00", g
    host, port = target
    addr = socket.inet_aton(socket.gethostbyname(host))
    s.send(b"\x05\x01\x00\x01" + addr + struct.pack(">H", port))
    r = s.recv(10)
    if r[1] != 0: return None
    # ClientHello имитируем любым байтом: наш тест-сервер отвечает R после 40% отбоя
    s.send(b"\x16")
    b = s.recv(1)
    s.close()
    return b
if __name__ == "__main__":
    proxy = (sys.argv[1], int(sys.argv[2]))
    target = (sys.argv[3], int(sys.argv[4]))
    n = int(sys.argv[5])
    ok = 0
    for i in range(n):
        r = probe(proxy, target)
        if r is not None: ok += 1
    print(f"{ok}/{n}")
