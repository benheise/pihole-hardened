#!/usr/bin/env python3
"""Fuzz the FTL web server and API: malformed HTTP, hostile query parameters and JSON bodies
on every endpoint, with and without a session. Watches for the server dying or hanging.
usage: api_fuzz.py <host:port> <endpoints.txt> [iterations] [seed]"""
import json, os, random, socket, sys, time, urllib.parse, http.client

HP = sys.argv[1]; host, port = HP.split(":"); port = int(port)
eps = [l.split()[0] for l in open(sys.argv[2]) if l.strip()]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
random.seed(int(sys.argv[4]) if len(sys.argv) > 4 else 7)

def Q(x, safe=""):
    return urllib.parse.quote(x.encode("utf-8", "surrogatepass") if isinstance(x, str) else x, safe=safe)

def raw(data, timeout=3, read=True):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.sendall(data)
        out = b""
        if read:
            try:
                while len(out) < 4096:
                    c = s.recv(4096)
                    if not c: break
                    out += c
            except Exception: pass
        s.close(); return out
    except Exception as e:
        return None

def login():
    for _ in range(40):
        try:
            c = http.client.HTTPConnection(host, port, timeout=8); c.request("POST", "/api/auth", json.dumps({"password": "test"}))
            j = json.loads(c.getresponse().read()); c.close()
            if j.get("session", {}).get("sid"): return j["session"]["sid"]
        except Exception: pass
        time.sleep(1.5)
    return None

def alive():
    for _ in range(4):
        r = raw(b"GET /api/info/login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 4)
        if r and b"200" in r[:20]: return True
        time.sleep(2)
    return False

NASTY = ["", "A" * 5000, "A" * 70000, "%s%s%s%n%n", "../../../../etc/passwd", "\x00", "%00", "'\" OR 1=1--", "';DROP TABLE queries;--", "\r\nX-Injected: 1",
         "-1", "0", "99999999999999999999999", "1e400", "NaN", "null", "true", "[]", "{}", "\ud800", "\xff\xfe", "$(id)", "`id`", "|id", ";id;", "{{7*7}}",
         "<script>x</script>", "*", "%", "_", "\\", "a" * 255 + ".example", "xn--" + "a" * 60, "0x7fffffff", "2147483648", "-2147483649", "18446744073709551616",
         "127.0.0.1", "::1", "::ffff:1.2.3.4", "1.2.3.4/33", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00:11:22", "(a+)+$", "(?:" * 200, "[" * 3000, "\\" * 4001]
def nasty():
    v = random.choice(NASTY)
    return v if random.random() < 0.85 else os.urandom(random.randrange(1, 300)).decode("latin-1")
def jval(depth=0):
    r = random.random()
    if r < 0.35: return nasty()
    if r < 0.5: return random.choice([0, -1, 2**31, 2**63, 2**64, -2**63 - 1, 1e308, 1.5, True, False, None])
    if r < 0.7 and depth < 6: return [jval(depth + 1) for _ in range(random.randrange(0, 5))]
    if depth < 6: return {random.choice(["config", "dns", "webserver", "api", "password", "totp", "domain", "comment", "groups", "enabled", "address", "client", "name", "type", "kind", "blocking", "timer", "items", "item", nasty()[:40]]): jval(depth + 1) for _ in range(random.randrange(0, 5))}
    return "x"
PARAMS = ["from", "until", "length", "start", "cursor", "domain", "client_ip", "client_name", "upstream", "type", "status", "reply", "dnssec", "disk", "N", "count", "blocked",
          "partial", "max_addresses", "max_devices", "nextID", "detailed", "sid", "debug", "full", "file", "restart", "show", "extended", "ref", "q"]

sid = login(); dead = 0; hangs = 0; t0 = time.time(); codes = {}
print("session:", bool(sid), flush=True)
for i in range(N):
    ep = random.choice(eps); r = random.random(); auth = random.random() < 0.8
    path = ep
    if random.random() < 0.5: path += "/" + Q(nasty()[:2000])
    if random.random() < 0.3: path += "/" + Q(nasty()[:300])
    if random.random() < 0.7:
        path += "?" + "&".join(Q(random.choice(PARAMS)) + "=" + Q(nasty()[:3000]) for _ in range(random.randrange(1, 6)))
    method = random.choice(["GET", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "FOO"])
    # never really wipe or reconfigure the box during fuzzing
    if ep.startswith(("/api/teleporter", "/api/action", "/api/auth")) and method != "GET" and auth: auth = False
    if ep.startswith("/api/config") and method in ("PATCH", "PUT", "DELETE") and auth and random.random() < 0.9: auth = False
    body = b""
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        if r < 0.6: body = json.dumps(jval()).encode("utf-8", "surrogatepass")
        elif r < 0.75: body = os.urandom(random.randrange(0, 2000))
        elif r < 0.85: body = b"[" * 20000
        elif r < 0.9: body = b'{"a":' * 5000 + b"1" + b"}" * 5000
        else: body = json.dumps({"config": jval()}).encode("utf-8", "surrogatepass")[:60000]
    hdrs = [f"{method} {path} HTTP/1.1", "Host: pi.hole"]
    if auth and sid: hdrs.append(f"sid: {sid}")
    if random.random() < 0.1: hdrs.append("X-Forwarded-For: " + nasty()[:500].replace("\r", "").replace("\n", ""))
    if random.random() < 0.05: hdrs.append("Cookie: sid=" + nasty()[:300].replace("\r", "").replace("\n", ""))
    if random.random() < 0.05: hdrs.append("Content-Type: multipart/form-data; boundary=" + nasty()[:200].replace("\r", "").replace("\n", ""))
    cl = len(body) if random.random() < 0.95 else random.choice([0, len(body) + 100, 2**31, -1])
    if body or method != "GET": hdrs.append(f"Content-Length: {cl}")
    if random.random() < 0.03: hdrs.append("Transfer-Encoding: chunked")
    hdrs.append("Connection: close")
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode("latin-1", "replace") + body
    if random.random() < 0.05:                       # raw protocol abuse
        req = random.choice([b"GET " + b"/" * 70000 + b" HTTP/1.1\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", os.urandom(800), b"GET /admin/ HTTP/1.1\r\n" + b"X: y\r\n" * 5000 + b"\r\n",
                             b"POST /api/auth HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n{", b"GET /admin/\x00.lp HTTP/1.1\r\nHost: x\r\n\r\n", req[: len(req) // 2]])
    if os.environ.get('SAVE') and i < int(os.environ['SAVE']): open(f"{os.environ.get('SAVEDIR','/tmp')}/req-{i:05d}.bin",'wb').write(req)
    t = time.time(); resp = raw(req, timeout=6)
    if time.time() - t > 5.5: hangs += 1
    code = resp[9:12].decode("latin-1", "replace") if resp and resp.startswith(b"HTTP/") else ("none" if not resp else "raw")
    codes[code] = codes.get(code, 0) + 1
    if code == "401" and auth: sid = login() or sid
    if i % 500 == 499:
        if not alive():
            dead += 1; print(f"  server not answering after request {i}: {method} {path[:120]!r}", flush=True); open(f"/tmp/apifuzz-last-{i}.bin", "wb").write(req); time.sleep(15); sid = login() or sid
    if i % 5000 == 4999: print(f"  {i+1} requests, {time.time()-t0:.0f}s, codes {dict(sorted(codes.items()))}", flush=True)
print(f"requests: {N}; server unresponsive at {dead} checkpoint(s); slow (>5.5 s) responses: {hangs}; status codes: {dict(sorted(codes.items()))}; alive at end: {alive()}")
