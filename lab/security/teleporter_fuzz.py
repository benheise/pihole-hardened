# mutated Teleporter uploads (zip and legacy tar.gz) against the sanitizer build
import io, json, os, random, sys, time, uuid, zipfile, tarfile, gzip, http.client
# usage: teleporter_fuzz.py <host:port> <uploads>   (admin password "test")
H, P = sys.argv[1].split(":"); P = int(P); N = int(sys.argv[2]); random.seed(21)
def call(method, path, body=None, headers=None, timeout=60):
    try:
        c = http.client.HTTPConnection(H, P, timeout=timeout); c.request(method, path, body, headers or {}); r = c.getresponse(); d = r.read(); c.close(); return r.status, d
    except Exception as e: return 0, b""
def login():
    for _ in range(60):
        s, d = call("POST", "/api/auth", json.dumps({"password": "test"}))
        if s == 200: return json.loads(d)["session"]["sid"]
        time.sleep(2)
def upload(sid, blob, name):
    b = uuid.uuid4().hex
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: application/zip\r\n\r\n').encode() + blob + f"\r\n--{b}--\r\n".encode()
    return call("POST", "/api/teleporter", body, {"sid": sid, "Content-Type": f"multipart/form-data; boundary={b}"})
sid = login(); s, exp = call("GET", "/api/teleporter", headers={"sid": sid}); z = zipfile.ZipFile(io.BytesIO(exp))
good = io.BytesIO()
with zipfile.ZipFile(good, "w", zipfile.ZIP_DEFLATED) as o:
    for n in ("etc/pihole/gravity.db", "etc/pihole/dhcp.leases"):
        if n in z.namelist(): o.writestr(n, z.read(n))        # no toml: avoids restarts
good = good.getvalue()
tb = io.BytesIO()
with tarfile.open(fileobj=tb, mode="w") as t:
    for n, d in (("adlist.json", b'[{"id":1,"address":"http://x/y","enabled":1,"date_added":1,"comment":"c"}]'), ("blacklist.exact.json", b"[]"), ("custom.list", b"1.2.3.4 a.b\n"), ("group.json", b"[]")):
        ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
rawtar = tb.getvalue(); codes = {}
for i in range(N):
    if i % 2 == 0:
        b = bytearray(good)
        for _ in range(random.randint(1, 14)): b[random.randrange(len(b))] = random.randrange(256)
        if i % 6 == 0:
            for _ in range(5): b[random.randrange(max(0, len(b) - 300), len(b))] = random.randrange(256)
        s, d = upload(sid, bytes(b), "t.zip")
    else:
        b = bytearray(rawtar)
        for _ in range(random.randint(1, 10)): b[random.randrange(len(b))] = random.randrange(256)
        if i % 3 == 0: off = 512 * random.randrange(0, len(b) // 512); b[off + 124: off + 135] = bytes(random.choice(b"01234567 \x00\xff") for _ in range(11))
        blob = gzip.compress(bytes(b))
        if i % 9 == 0: blob = blob[: random.randrange(10, len(blob))]
        s, d = upload(sid, blob, "t.tar.gz")
    codes[s] = codes.get(s, 0) + 1
    if s in (0, 401): sid = login() or sid
print("teleporter uploads:", sum(codes.values()), "status codes:", codes)
