#!/usr/bin/env python3
"""Add the Pi-hole components to Trivy's SBOMs.

Trivy inventories Alpine packages, but it can't identify the statically
linked pihole-FTL binary or the Pi-hole scripts and web files copied into
the image. The Dockerfile records each of those inputs (version, commit or
SHA-256) in /usr/share/pihole-hardened/build-inputs.txt; this script adds
them to the SPDX and CycloneDX documents in place.

With a fifth argument it also writes a small CycloneDX document holding only
the libraries compiled into pihole-FTL and bundled with the web interface, for
a separate, non-gating vulnerability scan (scan-image.sh).

usage: sbom-add-pihole.py <build-inputs.txt> <docker-pi-hole tag> <sbom.spdx.json> <sbom.cdx.json> [embedded.cdx.json]
"""
import json
import re
import sys
import uuid

inputs_path, docker_tag, spdx_path, cdx_path = sys.argv[1:5]

rec = {}
embedded = []   # (kind, name, version) lines written by scripts/embedded-components.sh
with open(inputs_path) as fh:
    for line in fh:
        parts = line.split()
        if not parts:
            continue
        if parts[0] in ("ftl-embedded", "web-vendor") and len(parts) >= 3:
            embedded.append((parts[0], parts[1], parts[2]))
        else:
            rec[parts[0]] = parts[1:]

# The startup scripts' commit is recorded when the build knows it (local builds may not)
docker_rec = rec.get("docker-pi-hole", [])
docker_commit = docker_rec[1] if len(docker_rec) > 1 and docker_rec[1] != "unknown" else None

SUPPLIER = "Pi-hole LLC"
LICENSE = "EUPL-1.2"
components = [
    {
        "key": "pihole-ftl", "name": "pihole-FTL", "version": rec["ftl"][0],
        "type": "application", "purl": f"pkg:github/pi-hole/FTL@{rec['ftl'][0]}",
        "sha256": rec["ftl"][1].removeprefix("sha256:"), "commit": None,
        "url": f"https://github.com/pi-hole/FTL/releases/tag/{rec['ftl'][0]}",
        "note": "Statically linked; the libraries compiled in are listed as separate components.",
    },
    {
        "key": "pihole-core", "name": "pi-hole", "version": rec["core"][0],
        "type": "application", "purl": f"pkg:github/pi-hole/pi-hole@{rec['core'][0]}",
        "sha256": None, "commit": rec["core"][1],
        "url": f"https://github.com/pi-hole/pi-hole/tree/{rec['core'][1]}", "note": None,
    },
    {
        "key": "pihole-web", "name": "pi-hole-web", "version": rec["web"][0],
        "type": "application", "purl": f"pkg:github/pi-hole/web@{rec['web'][0]}",
        "sha256": None, "commit": rec["web"][1],
        "url": f"https://github.com/pi-hole/web/tree/{rec['web'][1]}", "note": None,
    },
    {
        "key": "docker-pi-hole", "name": "docker-pi-hole", "version": docker_tag,
        "type": "application", "purl": f"pkg:github/pi-hole/docker-pi-hole@{docker_tag}",
        "sha256": None, "commit": docker_commit,
        "url": f"https://github.com/pi-hole/docker-pi-hole/tree/{docker_tag}",
        "note": "Startup scripts (start.sh, bash_functions.sh, prefix-time.sh, crontab).",
    },
    {
        "key": "macvendor-db", "name": "macvendor.db", "version": None,
        "type": "data", "purl": None,
        "sha256": rec["macvendor.db"][0].removeprefix("sha256:"), "commit": None,
        "url": "https://ftl.pi-hole.net/macvendor.db", "note": "MAC vendor database",
    },
]

# Libraries compiled into pihole-FTL and bundled with the web interface. They
# get a CPE (C libraries, for CPE-based matchers such as Grype) or an npm
# package URL (web libraries, for Trivy/Grype/OSV), so known CVEs can be matched.
FTL_LIBS = {  # name -> (display name, CPE vendor:product, upstream URL)
    "dnsmasq": ("dnsmasq (Pi-hole fork)", "thekelleys:dnsmasq", "https://github.com/pi-hole/dnsmasq"),
    "sqlite": ("SQLite", "sqlite:sqlite", "https://www.sqlite.org/"),
    "lua": ("Lua", "lua:lua", "https://www.lua.org/"),
    "nettle": ("Nettle", "nettle_project:nettle", "https://www.lysator.liu.se/~nisse/nettle/"),
    "civetweb": ("CivetWeb (modified by Pi-hole)", "civetweb_project:civetweb", "https://github.com/civetweb/civetweb"),
    "mbedtls": ("Mbed TLS", "arm:mbed_tls", "https://github.com/Mbed-TLS/mbedtls"),
    "tf-psa-crypto": ("TF-PSA-Crypto", "arm:tf-psa-crypto", "https://github.com/Mbed-TLS/TF-PSA-Crypto"),
    "cjson": ("cJSON", "cjson_project:cjson", "https://github.com/DaveGamble/cJSON"),
}
WEB_LIBS = {  # vendor directory -> npm package name
    "adminLTE": "admin-lte", "animate": "animate.css", "bootstrap": "bootstrap", "bootstrap-notify": "bootstrap-notify",
    "bootstrap-select": "bootstrap-select", "bootstrap-toggle": "bootstrap-toggle", "bstreeview": "bstreeview",
    "chartjs": "chart.js", "chartjs-adapter-moment": "chartjs-adapter-moment", "chartjs-plugin-deferred": "chartjs-plugin-deferred",
    "chartjs-plugin-zoom": "chartjs-plugin-zoom", "datatables": "datatables.net", "datatables-buttons": "datatables.net-buttons",
    "datatables-select": "datatables.net-select", "daterangepicker": "daterangepicker", "font-awesome": "@fortawesome/fontawesome-free",
    "hammer": "hammerjs", "icheck": "icheck", "jquery": "jquery", "jquery-confirm": "jquery-confirm", "moment": "moment",
    "nprogress": "nprogress", "qrious": "qrious", "select2": "select2", "waitMe-js": "waitme",
}
for kind, name, version in embedded:
    ver = None if version == "unknown" else version
    if kind == "ftl-embedded":
        disp, cpe_vp, url = FTL_LIBS.get(name, (name, None, "https://github.com/pi-hole/FTL"))
        # CPE and purl use the plain upstream number (pi-hole-v2.93+42 -> 2.93)
        m = re.search(r"\d+(?:\.\d+)+", ver or "")
        base = m.group(0) if m else None
        components.append({
            "key": f"ftl-{name}", "name": disp, "version": ver, "type": "library", "parent": "pihole-ftl",
            "purl": f"pkg:generic/{name}@{base}" if base else None,
            "cpe": f"cpe:2.3:a:{cpe_vp}:{base}:*:*:*:*:*:*:*" if cpe_vp and base else None,
            "sha256": None, "commit": None, "url": url, "license": None,
            "note": "Compiled into the static pihole-FTL binary.",
        })
    else:
        npm = WEB_LIBS.get(name, name)
        components.append({
            "key": "web-" + re.sub(r"[^A-Za-z0-9.-]", "-", name), "name": npm, "version": ver, "type": "library", "parent": "pihole-web",
            "purl": f"pkg:npm/{npm.replace('@', '%40')}@{ver}" if ver else None, "cpe": None,
            "sha256": None, "commit": None, "url": f"https://www.npmjs.com/package/{npm}", "license": None,
            "note": "Bundled in the web interface (vendor/).",
        })

# ---- SPDX 2.3 ----
def spdx_id_of(key):
    return f"SPDXRef-Package-{key}"

with open(spdx_path) as fh:
    spdx = json.load(fh)
root = next(r["relatedSpdxElement"] for r in spdx["relationships"]
            if r["spdxElementId"] == "SPDXRef-DOCUMENT" and r["relationshipType"] == "DESCRIBES")
existing = {p["SPDXID"] for p in spdx["packages"]}
for c in components:
    spdx_id = spdx_id_of(c["key"])
    if spdx_id in existing:
        continue
    third_party = "parent" in c            # embedded library, not Pi-hole's own code
    pkg = {
        "name": c["name"], "SPDXID": spdx_id,
        "downloadLocation": c["url"], "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION" if third_party or c["type"] == "data" else LICENSE,
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION" if third_party else f"Organization: {SUPPLIER}",
        "primaryPackagePurpose": {"application": "APPLICATION", "library": "LIBRARY"}.get(c["type"], "FILE"),
    }
    if c["version"]:
        pkg["versionInfo"] = c["version"]
    if c["sha256"]:
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": c["sha256"]}]
    refs_ = []
    if c["purl"]:
        refs_.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c["purl"]})
    if c.get("cpe"):
        refs_.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": c["cpe"]})
    if refs_:
        pkg["externalRefs"] = refs_
    notes = [n for n in (c["note"], c["commit"] and f"Source commit {c['commit']}") if n]
    if notes:
        pkg["comment"] = " ".join(notes)
    spdx["packages"].append(pkg)
    spdx["relationships"].append({"spdxElementId": spdx_id_of(c["parent"]) if third_party else root,
                                  "relatedSpdxElement": spdx_id, "relationshipType": "CONTAINS"})
with open(spdx_path, "w") as fh:
    json.dump(spdx, fh, indent=2)

# ---- CycloneDX ----
with open(cdx_path) as fh:
    cdx = json.load(fh)
root_ref = cdx["metadata"]["component"]["bom-ref"]
cdx.setdefault("components", [])
refs = {c.get("bom-ref") for c in cdx["components"]}
ref_of = {}
for c in components:
    ref_of[c["key"]] = c["purl"] or f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, c['url'] + '#' + c['key'])}"
new_refs, children = [], {}
for c in components:
    ref = ref_of[c["key"]]
    if ref in refs:
        continue
    third_party = "parent" in c
    comp = {"bom-ref": ref, "type": c["type"], "name": c["name"],
            "externalReferences": [{"type": "distribution" if c["sha256"] else ("website" if third_party else "vcs"), "url": c["url"]}]}
    if not third_party:
        comp["supplier"] = {"name": SUPPLIER}
    if c["version"]:
        comp["version"] = c["version"]
    if c["purl"]:
        comp["purl"] = c["purl"]
    if c.get("cpe"):
        comp["cpe"] = c["cpe"]
    if c["type"] != "data" and not third_party:
        comp["licenses"] = [{"license": {"id": LICENSE}}]
    if c["sha256"]:
        comp["hashes"] = [{"alg": "SHA-256", "content": c["sha256"]}]
    props = []
    if c["commit"]:
        props.append({"name": "pihole-hardened:source-commit", "value": c["commit"]})
    if c["note"]:
        props.append({"name": "pihole-hardened:note", "value": c["note"]})
    if props:
        comp["properties"] = props
    cdx["components"].append(comp)
    refs.add(ref)
    new_refs.append(ref)
    children.setdefault(ref_of[c["parent"]] if third_party else root_ref, []).append(ref)
deps = cdx.setdefault("dependencies", [])
by_ref = {d.get("ref"): d for d in deps}
for parent, kids in children.items():
    by_ref.setdefault(parent, None)
    if by_ref[parent] is None:
        by_ref[parent] = {"ref": parent, "dependsOn": []}
        deps.append(by_ref[parent])
    by_ref[parent].setdefault("dependsOn", []).extend(k for k in kids if k not in by_ref[parent]["dependsOn"])
for r in new_refs:
    if r not in by_ref:
        deps.append({"ref": r, "dependsOn": []})
with open(cdx_path, "w") as fh:
    json.dump(cdx, fh, indent=2)

if len(sys.argv) > 5:
    emb_refs = {ref_of[c["key"]] for c in components if "parent" in c}
    emb = {
        "bomFormat": "CycloneDX", "specVersion": cdx.get("specVersion", "1.6"), "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, cdx.get('serialNumber', cdx_path) + '#embedded')}",
        "metadata": {"component": {"bom-ref": "pihole-hardened-embedded", "type": "application",
                                   "name": "pihole-hardened embedded components"}},
        "components": [c for c in cdx["components"] if c.get("bom-ref") in emb_refs],
    }
    with open(sys.argv[5], "w") as fh:
        json.dump(emb, fh, indent=2)

own = sum(1 for c in components if "parent" not in c)
print(f"SBOMs: {own} Pi-hole components, {len(components) - own} embedded libraries ({len(new_refs)} added in this run)")
