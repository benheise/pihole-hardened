#!/usr/bin/env python3
"""DNS behaviour checks run from a LAN client. usage: dns_tests.py <server> <mode>
modes: ratelimit | amplify | fuzz [n] [seed]"""
import os, random, socket, struct, sys, time, collections

S = sys.argv[1]; mode = sys.argv[2]; PORT = int(os.environ.get("DNS_PORT", "53"))

def q(name, qtype=1, edns=None, flags=0x0100, do=False, rid=None):
    rid = rid if rid is not None else random.randrange(65536)
    p = struct.pack(">HHHHHH", rid, flags, 1, 0, 0, 1 if edns else 0)
    for l in name.rstrip(".").split("."):
        b = l.encode("latin-1"); p += bytes([len(b)]) + b
    p += b"\0" + struct.pack(">HH", qtype, 1)
    if edns: p += b"\0" + struct.pack(">HHIH", 41, edns, 0x8000 if do else 0, 0)
    return p

def ask(pkt, timeout=1.5, tcp=False):
    try:
        if tcp:
            s = socket.create_connection((S, PORT), timeout=timeout); s.sendall(struct.pack(">H", len(pkt)) + pkt)
            d = s.recv(65535); s.close(); return d[2:]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout); s.sendto(pkt, (S, PORT)); d, _ = s.recvfrom(65535); s.close(); return d
    except Exception:
        return None

def alive():
    for _ in range(3):
        d = ask(q("pi.hole"), 2)
        if d and len(d) > 12: return True
        time.sleep(1)
    return False

if mode == "ratelimit":
    rc = collections.Counter(); t0 = time.time(); first_refused = None
    for i in range(2500):
        d = ask(q(f"rl{i}.ok.lab.example"), 1)
        code = (d[3] & 15) if d else "timeout"; rc[code] += 1
        if code == 5 and first_refused is None: first_refused = i
    print(f"2500 queries in {time.time()-t0:.1f}s; rcodes {dict(rc)}; first REFUSED at query #{first_refused}")
    d = ask(q("pi.hole")); print("normal query right after:", (d[3] & 15) if d else "timeout", "(5 = REFUSED)")

elif mode == "amplify":
    for name, qt, label in [("ok.lab.example", 1, "A"), ("ok.lab.example", 255, "ANY"), ("big.lab.example", 16, "TXT (4 kB record upstream)"),
                            ("pi.hole", 255, "ANY pi.hole"), ("version.bind", 16, "CHAOS-ish"), (".", 2, "NS root"), ("lab.example", 6, "SOA")]:
        for edns in (None, 1232, 4096):
            pkt = q(name, qt, edns=edns, do=bool(edns)); d = ask(pkt)
            if d: print(f"{label:28} edns={str(edns):5} query {len(pkt):3} B -> response {len(d):5} B  x{len(d)/len(pkt):.1f}  rcode {d[3]&15} tc={(d[2]>>1)&1}")
            else: print(f"{label:28} edns={str(edns):5} query {len(pkt):3} B -> no answer")

elif mode == "fuzz":
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 20000; random.seed(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    seeds = [q("ok.lab.example"), q("ok.lab.example", 28, edns=1232, do=True), q("a." * 60 + "example", 16), q("pi.hole", 255, edns=4096),
             q("x.lab.example", 12), q("50.50.31.172.in-addr.arpa", 12), q("ok.lab.example", 1, flags=0x2800), q("ok.lab.example", 251),
             q("ok.lab.example", 65, edns=1232), q("ok.lab.example", 1, edns=512) + b"\x00\x08\x00\x08\x00\x01\x18\x00\xac\x1f\x32\x00"]
    dead = 0; sent = 0
    for i in range(n):
        b = bytearray(random.choice(seeds)); r = random.random()
        if r < 0.5:
            for _ in range(random.randint(1, 6)): b[random.randrange(len(b))] = random.randrange(256)
        elif r < 0.7: b = b[: random.randrange(1, len(b))]
        elif r < 0.85: b += os.urandom(random.randrange(1, 600))
        elif r < 0.95:
            p = random.randrange(12, len(b)); b[p:p] = bytes([0xC0, random.randrange(256)]) * random.randrange(1, 40)   # compression pointers / loops
        else: b[4:12] = struct.pack(">HHHH", *(random.choice([0, 1, 255, 65535]) for _ in range(4)))
        try:
            if i % 10 == 0:
                s = socket.create_connection((S, PORT), timeout=1); ln = random.choice([len(b), 0, 65535, len(b) + 50, 1])
                s.sendall(struct.pack(">H", ln) + bytes(b)); s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(bytes(b), (S, PORT)); s.close()
            sent += 1
        except Exception:
            pass
        if i % 2000 == 1999 and not alive():
            dead += 1; print(f"  not answering after packet {i}"); time.sleep(10)
    print(f"sent {sent} malformed DNS packets; resolver unresponsive at {dead} checkpoint(s); alive at end: {alive()}")
