import socket, struct, json, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53)); s.settimeout(1); rec = []; end = time.time() + float(sys.argv[1])
while time.time() < end:
    try: d, (ip, port) = s.recvfrom(4096)
    except socket.timeout: continue
    txid = struct.unpack(">H", d[:2])[0]; i = 12; labels = []
    while d[i]: labels.append(d[i+1:i+1+d[i]].decode("latin-1")); i += 1 + d[i]
    rec.append({"port": port, "txid": txid, "name": ".".join(labels), "edns": len(d) > i + 5})
    s.sendto(d[:2] + b"\x81\x82" + d[4:], (ip, port))            # SERVFAIL
json.dump(rec, open("/work/upstream-queries.json", "w"))
