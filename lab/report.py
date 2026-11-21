#!/usr/bin/env python3
"""Build LAB-REPORT.md from the lab's JSON-lines results.

usage: report.py <results-dir>   (writes <results-dir>/LAB-REPORT.md)
"""
import json
import sys
from pathlib import Path

res = Path(sys.argv[1])


def load(name):
    p = res / f"{name}.jsonl"
    if not p.exists():
        return {}
    rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    return {r["id"]: r for r in rows}


control, subject, variants = load("control"), load("subject"), load("variants")
meta = json.loads((res / "meta.json").read_text()) if (res / "meta.json").exists() else {}
mark = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "INFO": "ℹ️ info", "SKIP": "⏭ skip"}

core_ids = [i for i in subject if not i.startswith("P") and subject[i]["status"] != "INFO"]
posture_ids = [i for i in subject if i.startswith("P")]
info_ids = [i for i in subject if not i.startswith("P") and subject[i]["status"] == "INFO"]

core_pass = sum(subject[i]["status"] == "PASS" for i in core_ids)
mismatch = [i for i in core_ids if control.get(i, {}).get("status") != subject[i]["status"]]
posture_pass = sum(subject[i]["status"] == "PASS" for i in posture_ids)
v_pass = sum(v["status"] == "PASS" for v in variants.values())
v_fail = [i for i, v in variants.items() if v["status"] == "FAIL"]
v_skip = [i for i, v in variants.items() if v["status"] == "SKIP"]
ok = (core_ids and core_pass == len(core_ids) and not mismatch
      and posture_pass == len(posture_ids) and not v_fail)

out = ["# Lab report — hardened Pi-hole vs. official image", ""]
if meta:
    out += [f"- **Run:** {meta.get('date', '?')} on {meta.get('docker', '?')} ({meta.get('arch', '?')})",
            f"- **Control:** `{meta.get('control_image')}` (`{meta.get('control_id', '?')[:19]}`)",
            f"- **Subject:** `{meta.get('subject_image')}` (`{meta.get('subject_id', '?')[:19]}`)",
            f"- **Plan:** `lab/LAB-PLAN.md`; raw results: `*.jsonl` in this folder", ""]

out += ["## Verdict", "",
        f"**{'PASS' if ok else 'FAIL'}** — the hardened image "
        + ("keeps every tested capability of the official image and meets every hardening check."
           if ok else "does not meet every criterion; see the failures below."), "",
        "| Area | Result |", "|---|---|",
        f"| Core capabilities (subject) | {core_pass}/{len(core_ids)} pass |",
        f"| Parity with control | {len(core_ids) - len(mismatch)}/{len(core_ids)} identical |",
        f"| Runtime posture (subject) | {posture_pass}/{len(posture_ids)} pass |",
        f"| Variant scenarios | {v_pass} pass, {len(v_fail)} fail, {len(v_skip)} skipped |", ""]

out += ["## Core capabilities", "", "| ID | Capability | Control | Subject | Same? | Subject detail |",
        "|---|---|---|---|---|---|"]
for i in sorted(core_ids):
    c, s = control.get(i, {}), subject[i]
    same = "✓" if c.get("status") == s["status"] else "**✗**"
    out.append(f"| {i} | {s['name']} | {mark.get(c.get('status'), '—')} | {mark[s['status']]} | {same} "
               f"| {s['detail'].replace('|', '/')[:80]} |")

if info_ids:
    out += ["", "## Measurements (not pass/fail)", "", "| ID | Measure | Control | Subject |", "|---|---|---|---|"]
    for i in info_ids:
        out.append(f"| {i} | {subject[i]['name']} | {control.get(i, {}).get('detail', '—')} | {subject[i]['detail']} |")

out += ["", "## Runtime posture", "", "Pass/fail applies to the subject; control values are shown for comparison.", "",
        "| ID | Check | Control | Subject | Result |", "|---|---|---|---|---|"]
for i in sorted(posture_ids):
    s = subject[i]
    val = s["detail"] if s["status"] == "PASS" else s["detail"].split("'")[1] if "'" in s["detail"] else s["detail"]
    out.append(f"| {i} | {s['name']} | `{control.get(i, {}).get('detail', '—')[:60]}` | `{val[:60]}` | {mark[s['status']]} |")

out += ["", "## Variant scenarios", "", "| ID | Scenario | Result | Detail |", "|---|---|---|---|"]
for i in sorted(variants):
    v = variants[i]
    out.append(f"| {i} | {v['name']} | {mark[v['status']]} | {v['detail'].replace('|', '/')[:110]} |")

problems = ([f"- **{i} {subject[i]['name']}** (subject): {subject[i]['detail']}" for i in core_ids + posture_ids
             if subject[i]["status"] == "FAIL"]
            + [f"- **{i} {subject[i]['name']}**: control={control.get(i, {}).get('status')} "
               f"subject={subject[i]['status']}" for i in mismatch]
            + [f"- **{i} {variants[i]['name']}**: {variants[i]['detail']}" for i in v_fail])
out += ["", "## Failures and mismatches", ""] + (problems or ["None."])
(res / "LAB-REPORT.md").write_text("\n".join(out) + "\n")
print(f"wrote {res / 'LAB-REPORT.md'}: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
