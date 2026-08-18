#!/usr/bin/env python3
"""最小 STUN Binding 请求：探测 UDP 路径的公网出口 IP（WebRTC 泄漏走的就是这条路）"""
import socket, struct, os, sys

SERVERS = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]
MAGIC = 0x2112A442

def query(host, port):
    tid = os.urandom(12)
    msg = struct.pack("!HHI", 0x0001, 0, MAGIC) + tid  # Binding Request
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(msg, (host, port))
        data, _ = s.recvfrom(2048)
    finally:
        s.close()
    if len(data) < 20 or data[8:20] != tid:
        return None
    pos, end = 20, 20 + struct.unpack("!H", data[2:4])[0]
    while pos + 4 <= min(end, len(data)):
        atype, alen = struct.unpack("!HH", data[pos:pos+4])
        val = data[pos+4:pos+4+alen]
        if atype in (0x0020, 0x0001) and len(val) >= 8:  # XOR-MAPPED / MAPPED
            fam, xport = struct.unpack("!xBH", val[:4])
            if fam == 0x01:
                ip_int = struct.unpack("!I", val[4:8])[0]
                if atype == 0x0020:
                    ip_int ^= MAGIC
                return socket.inet_ntoa(struct.pack("!I", ip_int))
        pos += 4 + alen + ((4 - alen % 4) % 4)
    return None

for host, port in SERVERS:
    try:
        ip = query(host, port)
        if ip:
            print(ip)
            sys.exit(0)
    except Exception:
        continue
print("")  # UDP 全部不通
sys.exit(1)
