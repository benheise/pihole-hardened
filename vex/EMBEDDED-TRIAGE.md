# Embedded components: what the known CVEs mean for this image

`pihole-FTL` is one static binary with its libraries compiled in (dnsmasq,
SQLite, Lua, CivetWeb, Mbed TLS, TF-PSA-Crypto, nettle, cJSON), and the web
interface ships its JavaScript libraries as files. No package scanner sees
either in the image, so the build records them (`scripts/embedded-components.sh`),
`scripts/sbom-add-pihole.py` adds them to the SBOMs, and every release scans
them from there with Trivy and Grype.

These findings never block a release. This project cannot fix them: it uses
upstream's released binary and web files unchanged, so a fix arrives with a
new Pi-hole release, which Renovate proposes. The table below is the manual
judgement that a scanner cannot make. It is reviewed when the pinned Pi-hole
versions change and whenever the release report lists an ID that is not here.

Matching is by version number. The dnsmasq inside FTL is Pi-hole's fork and
CivetWeb is modified, so a match (or the absence of one) for those two is a
prompt to read the fork's source, not a verdict.

## Triage (FTL v6.9, Web v6.6.1; reviewed 2026-11-20)

| ID | Component | Reachable here? | Notes |
|---|---|---|---|
| CVE-2026-119586 | SQLite 3.54.1 | Yes, narrowly | The SQLite shell's `.recover` writes out commands planted in a damaged database. `pihole -g -r recover` uses `.recover` on the gravity database. It runs as the `pihole` user and the database is writable only by that user, so it crosses no privilege boundary in this image. Do not run the recover command on a database file from an untrusted source. Included in the findings report prepared for upstream. |
| CVE-2025-66442 | Mbed TLS 4.0.0, TF-PSA-Crypto 1.0.0 | No | Timing side channel in RSA and CBC/ECB decryption introduced by LLVM's optimiser. FTL release binaries are built with GCC 15.2, and FTL's TLS certificate is ECDSA. |
| CVE-2026-34872 | TF-PSA-Crypto 1.0.0 | No | Finite-field Diffie-Hellman accepts degenerate public values. FTL's TLS server offers only elliptic-curve (ECDHE) key exchange, confirmed by a cipher-suite scan of the running image. |
| CVE-2024-6485, CVE-2025-1647 | Bootstrap 3.4.1 | Not found | Cross-site scripting through `data-*` attributes of buttons, tooltips and popovers. It needs attacker-controlled markup in the page. The 2026-11-20 review sent hostile names through every path a LAN client controls (DNS queries, reverse lookups, DHCP hostnames) and found none rendered as markup; the content security policy (`script-src 'self'`) blocks inline script as a second layer. Bootstrap 3 is end-of-life, so no fixed 3.x release exists. |
| CVE-2020-28458, CVE-2021-23445 | DataTables 1.10.21 | Not found | Prototype pollution through crafted column names, and incomplete HTML escaping when an array is passed to the escape helper. Column definitions in the web interface are fixed in code, and the same hostile-name tests found no unescaped output. Fixed in 1.10.22 and 1.11.3. |

Checked by hand and not matched by the scanners:

| ID | Component | Status |
|---|---|---|
| CVE-2026-12725, CVE-2026-12969 | dnsmasq before 2.93 | Fixed. FTL v6.9 embeds the fork at `pi-hole-v2.93+42`, and the corrected length check in `find_soa()` is present in its source. |
| none known | Lua 5.5.0, CivetWeb 1.17, cJSON 1.7.18, nettle 3.10 | No CVE listed for these versions in the NVD on the review date. |

miniz, tomlc17 and tre-regex are also compiled into FTL but print no version,
so they are not in the SBOM. FTL's source tree for the pinned tag is the
reference for those.
