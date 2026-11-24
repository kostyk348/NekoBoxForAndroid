# DNS-запрос через SOCKS5 UDP ASSOCIATE: полное рукопожатие + датаграмма.
import socket, struct, sys, random
def main():
    phost, pport = sys.argv[1], int(sys.argv[2])
    s = socket.socket(); s.settimeout(8)
    s.connect((phost, pport))
    s.send(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
    # UDP ASSOCIATE, DST 0.0.0.0:0
    s.send(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
    r = s.recv(10)
    assert r[1] == 0, r
    bnd_port = struct.unpack(">H", r[8:10])[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(8)
    u.bind((phost, 0))
    # DNS: A? example.com
    tid = random.randrange(65536)
    q = tid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
    pkt = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53) + q
    u.sendto(pkt, (phost, bnd_port))
    data, _ = u.recvfrom(4096)
    print("dns ok, len", len(data), "id-ok:", data[:2] == tid.to_bytes(2, "big"))
if __name__ == "__main__":
    main()
