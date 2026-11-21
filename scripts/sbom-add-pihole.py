#!/usr/bin/env python3
"""Add the Pi-hole components to Trivy's SBOMs.

Trivy inventories Alpine packages, but it can't identify the statically
linked pihole-FTL binary or the Pi-hole scripts and web files copied into
the image. The Dockerfile records each of those inputs (version, commit or
SHA-256) in /usr/share/pihole-hardened/build-inputs.txt; this script adds
them to the SPDX and CycloneDX documents in place.

usage: sbom-add-pihole.py <build-inputs.txt> <docker-pi-hole tag> <sbom.spdx.json> <sbom.cdx.json>
"""
import json
import sys
import uuid

inputs_path, docker_tag, spdx_path, cdx_path = sys.argv[1:5]

rec = {}
with open(inputs_path) as fh:
    for line in fh:
        parts = line.split()
        if parts:
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
        "note": "Statically linked; embedded third-party libraries are not enumerated.",
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

# ---- SPDX 2.3 ----
with open(spdx_path) as fh:
    spdx = json.load(fh)
root = next(r["relatedSpdxElement"] for r in spdx["relationships"]
            if r["spdxElementId"] == "SPDXRef-DOCUMENT" and r["relationshipType"] == "DESCRIBES")
existing = {p["SPDXID"] for p in spdx["packages"]}
for c in components:
    spdx_id = f"SPDXRef-Package-{c['key']}"
    if spdx_id in existing:
        continue
    pkg = {
        "name": c["name"], "SPDXID": spdx_id,
        "downloadLocation": c["url"], "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": LICENSE if c["type"] != "data" else "NOASSERTION",
        "copyrightText": "NOASSERTION", "supplier": f"Organization: {SUPPLIER}",
        "primaryPackagePurpose": "APPLICATION" if c["type"] == "application" else "FILE",
    }
    if c["version"]:
        pkg["versionInfo"] = c["version"]
    if c["sha256"]:
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": c["sha256"]}]
    if c["purl"]:
        pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                "referenceLocator": c["purl"]}]
    notes = [n for n in (c["note"], c["commit"] and f"Source commit {c['commit']}") if n]
    if notes:
        pkg["comment"] = " ".join(notes)
    spdx["packages"].append(pkg)
    spdx["relationships"].append({"spdxElementId": root, "relatedSpdxElement": spdx_id,
                                  "relationshipType": "CONTAINS"})
with open(spdx_path, "w") as fh:
    json.dump(spdx, fh, indent=2)

# ---- CycloneDX ----
with open(cdx_path) as fh:
    cdx = json.load(fh)
root_ref = cdx["metadata"]["component"]["bom-ref"]
cdx.setdefault("components", [])
refs = {c.get("bom-ref") for c in cdx["components"]}
new_refs = []
for c in components:
    ref = c["purl"] or f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, c['url'])}"
    if ref in refs:
        continue
    comp = {"bom-ref": ref, "type": c["type"], "name": c["name"], "supplier": {"name": SUPPLIER},
            "externalReferences": [{"type": "distribution" if c["sha256"] else "vcs", "url": c["url"]}]}
    if c["version"]:
        comp["version"] = c["version"]
    if c["purl"]:
        comp["purl"] = c["purl"]
    if c["type"] != "data":
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
    new_refs.append(ref)
deps = cdx.setdefault("dependencies", [])
root_dep = next((d for d in deps if d.get("ref") == root_ref), None)
if root_dep is None:
    root_dep = {"ref": root_ref, "dependsOn": []}
    deps.append(root_dep)
root_dep.setdefault("dependsOn", []).extend(new_refs)
for r in new_refs:
    deps.append({"ref": r, "dependsOn": []})
with open(cdx_path, "w") as fh:
    json.dump(cdx, fh, indent=2)

print(f"added {len(new_refs)} Pi-hole components to SPDX and CycloneDX")
