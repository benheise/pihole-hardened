#!/usr/bin/env python3
"""Hostile list server for gravity tests (runs in the client container on :8000)."""
import gzip, http.server, io, os, zlib

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype="text/plain", extra=()):
        self.send_response(200); self.send_header("Content-Type", ctype)
        for k, v in extra: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p.startswith("/redir-"):
            target = {"file": "file:///etc/passwd", "gopher": "gopher://127.0.0.1:80/_GET%20/", "dict": "dict://127.0.0.1:53/",
                      "local": "http://127.0.0.1/api/info/login", "ftp": "ftp://172.31.50.50/x"}[p[7:]]
            self.send_response(302); self.send_header("Location", target); self.end_headers(); return
        if p == "/ok": return self._send(b"good1.lab.example\ngood2.lab.example\n")
        if p == "/bigline": return self._send(b"a" * (20 << 20) + b".example\nafter-big.lab.example\n")
        if p == "/binary": return self._send(os.urandom(1 << 20) + b"\nafter-binary.lab.example\n")
        if p == "/nul": return self._send(b"nul\0byte.lab.example\nafter-nul.lab.example\n" * 1000)
        if p == "/html": return self._send(b"<html><script>alert(1)</script>\n<img src=x onerror=__xss_list=1>\n$(id>/tmp/list_cmd)\n`id>/tmp/list_cmd2`\n;id>/tmp/list_cmd3;\n-oProxyCommand=id\n../../../etc/passwd\nok-after-html.lab.example\n")
        if p == "/many":
            body = b"".join(b"d%07d.many.lab.example\n" % i for i in range(3_000_000))
            return self._send(body)
        if p == "/gzbomb":
            c = zlib.compressobj(9, zlib.DEFLATED, 31); out = io.BytesIO(); chunk = b"0" * (1 << 20)
            for _ in range(2048): out.write(c.compress(chunk))      # 2 GiB when inflated
            out.write(c.flush())
            return self._send(out.getvalue(), extra=[("Content-Encoding", "gzip")])
        if p == "/abp": return self._send(b"[Adblock Plus]\n||abp1.lab.example^\n||*.wild.lab.example^\n@@||allow.lab.example^\n||bad domain with space^\n||" + b"x" * 300 + b".example^\n")
        if p == "/slow":
            self.send_response(200); self.end_headers()
            import time
            for _ in range(600): self.wfile.write(b"s.lab.example\n"); self.wfile.flush(); time.sleep(1)
            return
        self.send_response(404); self.end_headers()

http.server.ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
