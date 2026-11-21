#!/usr/bin/env python3
"""Log in to the Pi-hole web UI with a headless browser, visit every page that
shows DNS-derived or stored data, and report whether any injected payload ran
(window.__xss_* set, dialogs) or landed in the DOM as markup.
usage: xss_check.py <base-url> <password> [extra-path ...]"""
import sys, json
from playwright.sync_api import sync_playwright

base, pw = sys.argv[1], sys.argv[2]
pages = ["/admin/", "/admin/queries", "/admin/network", "/admin/groups", "/admin/groups/clients",
         "/admin/groups/domains", "/admin/groups/lists", "/admin/messages", "/admin/taillog",
         "/admin/taillog?webserver", "/admin/taillog?ftl", "/admin/search", "/admin/interfaces",
         "/admin/settings/system", "/admin/settings/dns", "/admin/settings/dhcp", "/admin/settings/dnsrecords",
         "/admin/settings/api", "/admin/settings/privacy", "/admin/settings/teleporter", "/admin/settings/all",
         "/admin/gravity"] + sys.argv[3:]

PROBE = """() => {
  const flags = Object.keys(window).filter(k => k.startsWith('__xss'));
  const sel = 'img[src="x"], svg[onload], [onmouseover*="__xss"], [onerror*="__xss"], script:not([src])';
  const nodes = [...document.querySelectorAll(sel)].filter(n => n.tagName !== 'SCRIPT' || /__xss/.test(n.textContent))
     .map(n => n.outerHTML.slice(0, 160));
  const textHits = (document.body.innerText.match(/__xss_[a-z0-9]+/g) || []);
  return {flags, nodes, shownAsText: [...new Set(textHits)].length};
}"""

results, dialogs = [], []
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-proxy-server", "--ignore-certificate-errors"])
    ctx = b.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.goto(base + "/admin/login", wait_until="networkidle")
    page.fill("#current-password", pw)
    page.keyboard.press("Enter")
    page.wait_for_function("() => !location.pathname.endsWith('/login')", timeout=15000)
    for path in pages:
        try:
            page.goto(base + path, wait_until="networkidle", timeout=30000)
        except Exception as e:
            results.append({"page": path, "error": str(e)[:80]}); continue
        page.wait_for_timeout(2500)
        # open expandable rows / details where present
        for sel in ["table tbody tr td.details-control", "table tbody tr", "#top-domains tr a", "#client-frequency tr a"]:
            try:
                els = page.query_selector_all(sel)[:6]
                for e in els:
                    e.hover(timeout=500)
                    if "details" in sel or sel == "table tbody tr":
                        e.click(timeout=500, trial=False)
            except Exception:
                pass
        page.wait_for_timeout(800)
        r = page.evaluate(PROBE); r["page"] = path; r["url"] = page.url.replace(base, "")
        results.append(r)
    b.close()

bad = 0
for r in results:
    state = "ERROR " + r["error"] if "error" in r else ("EXECUTED/INJECTED" if (r["flags"] or r["nodes"]) else "ok")
    if "error" not in r and (r["flags"] or r["nodes"]): bad += 1
    print(f'{r["page"]:34} {state:18} payload strings shown as text: {r.get("shownAsText", "-")}' + (f'  -> {r.get("url")}' if r.get("url") != r["page"] else ""))
    for n in r.get("nodes", []): print("      node:", n)
    if r.get("flags"): print("      flags:", r["flags"])
print("dialogs:", dialogs)
print("RESULT:", "XSS FOUND on %d page(s)" % bad if bad or dialogs else "no payload executed or injected as markup")
