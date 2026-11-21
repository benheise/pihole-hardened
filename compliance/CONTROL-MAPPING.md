# Control mapping — what this pipeline provides evidence for

This document maps the image, the pipeline and each release's compliance
bundle to the frameworks a security assessor is likely to ask about. It
describes **evidence**, not compliance: whether a system is compliant depends
on the whole environment and on practices this repository can't see.

**Not authorized for CUI.** Don't place this system inside a CUI enclave. If
it ever serves one, it becomes a Security Protection Asset under CMMC Level 2
(32 CFR 170.19), and this mapping is not sufficient.

## CMMC Level 1 (FCI)

Level 1 covers the 15 safeguarding requirements in FAR 52.204-21(b)(1)(i)–(xv).
The table in 32 CFR 170.15 splits three of them into separate phrases, which
is why some sources count 17. Level 1 requires an annual self-assessment
entered in SPRS and an affirmation by a senior official.

Whether a DNS filter is inside your Level 1 assessment boundary depends on how
you've drawn it. Many organizations treat it as part of boundary protection
(SC.L1-b.1.x).

| Practice | Requirement (short) | What this repository provides | Evidence | Still yours |
|---|---|---|---|---|
| AC.L1-b.1.i | Limit access to authorized users, processes, devices | Admin password from a secret file; admin UI published on localhost only; GHCR and repository access through GitHub accounts | `deploy/docker-compose.yml`, repository settings | User accounts, MFA, who can reach the admin UI |
| AC.L1-b.1.ii | Limit to authorized transactions and functions | FTL runs as a dedicated non-root UID with no effective capabilities; 7 of Docker's 14 default capabilities; `no-new-privileges`; least-privilege `GITHUB_TOKEN` per job | Lab posture checks P01–P07 (`lab-report-*.md`); workflow `permissions:` blocks | Host and Docker daemon access |
| AC.L1-b.1.iii | Verify and control connections to external systems | Upstream DNS servers are explicit configuration | `pihole.toml` / `FTLCONF_dns_upstreams` | Firewall rules, approved upstreams |
| AC.L1-b.1.iv | Control publicly posted information | Public repository and image contain no FCI or secrets | Secret scanning, review | Keep FCI out of issues, logs and configs |
| IA.L1-b.1.v | Identify users, processes, devices | Each release names the exact workflow that built and signed it (Sigstore keyless identity) | `cosign verify` output, SLSA provenance | User identification |
| IA.L1-b.1.vi | Authenticate before access | API and web UI require the admin password | Lab test M01 | Password policy, MFA for GitHub |
| MP.L1-b.1.vii | Sanitize media | — | — | Yours |
| PE.L1-b.1.viii | Limit physical access | — | — | Yours (where the Pi lives) |
| PE.L1-b.1.ix | Escort visitors, logs, physical access devices | — | — | Yours |
| SC.L1-b.1.x | Monitor, control, protect communications at boundaries | DNS-layer filtering with logged queries; blocking verified each release | Lab tests B01–B17, M03 | Network design, firewall |
| SC.L1-b.1.xi | Separate publicly accessible components | — | — | Network segmentation |
| SI.L1-b.1.xii | Identify, report and correct flaws in a timely manner | Renovate tracks upstream and base updates; weekly rebuild; release blocked on fixable HIGH/CRITICAL; upstream bugs reported | `vulnerability-report.md`, scan SARIF in code scanning, Renovate PR history, release history | Patch deployment SLA; the Pi's host OS |
| SI.L1-b.1.xiii | Malicious code protection | Blocks DNS resolution of listed malicious domains; deploys only signed, verified images | Lab blocking tests; `verify-release.sh` | Endpoint anti-malware (DNS filtering is partial coverage) |
| SI.L1-b.1.xiv | Update malicious code protection | Blocklists refresh weekly (gravity cron); scanner databases refresh on every run | Lab test M05; workflow logs | Choice of blocklists |
| SI.L1-b.1.xv | Periodic scans; scan files from external sources | Every build and weekly rebuild is scanned; the image (an external download) is verified before deployment | Scan reports per release; `deploy/update.sh` | Scanning other systems |

## NIST SP 800-190 (Application Container Security Guide)

| Risk area (§4) | Countermeasure (§5) | Implementation |
|---|---|---|
| 4.1.1 Image vulnerabilities | Scan images, block noncompliant images | Trivy and Grype gates on every platform; weekly rebuild; VEX for documented exceptions |
| 4.1.2 Image configuration defects | Validate configuration, minimal images | hadolint and `trivy config` in CI; no package manager, no setuid binaries; build-only tools excluded |
| 4.1.3 Embedded malware | Trusted sources, scanning | Upstream inputs pinned by version and verified (FTL checksum, Alpine digest) |
| 4.1.4 Embedded clear-text secrets | Keep secrets out of images | Admin password supplied at runtime from a secret file |
| 4.1.5 Use of untrusted images | Only signed images from trusted sources | Keyless signatures and SLSA provenance; deploy by digest after `verify-release.sh` |
| 4.2.1–4.2.3 Registry risks | Encrypted connections, prune stale images, access control | GHCR over TLS; images referenced by digest; GitHub access controls |
| 4.4.3 Insecure container runtime configuration | Least privilege at runtime | `cap_drop: ALL` + 7 capabilities, `no-new-privileges`, PID and memory limits, non-root FTL |
| 4.4.2 Unbounded network access | Limit exposure | Only DNS published to the LAN; admin UI on localhost |
| 4.5 Host OS risks | Container-specific host OS, hardening | Out of scope: the Raspberry Pi host |

## NIST SSDF (SP 800-218 v1.1)

| Practice | Implementation |
|---|---|
| PO.3 Implement supporting toolchains | Actions pinned to commit SHAs; StepSecurity Harden-Runner; Trivy installed from a version-pinned release whose tarball hash is pinned in `upstream.env` (reviewed by a person on every bump) |
| PS.1 Protect all forms of code | Branch ruleset on `main`; required checks; PR-only changes |
| PS.2 Provide a mechanism for verifying release integrity | Cosign keyless signatures on the image and the checksum manifest |
| PS.3 Archive and protect each release | Immutable GitHub releases with SBOMs, provenance and scan results |
| PW.4 Reuse existing, well-secured software | Upstream Pi-hole and Alpine pinned by version/digest; package drift check against upstream; every release records what each upstream tag resolved to, and the next release refuses to publish if a tag's content moved without its name changing (`scripts/check-upstream-drift.sh`) |
| PW.7 / PW.8 Review and test | Lint gates; smoke test; functional parity lab (official vs. hardened) on amd64 and arm64 before every release |
| RV.1 Identify vulnerabilities on an ongoing basis | Weekly rebuild and scan; SARIF in GitHub code scanning; Renovate |
| RV.2 Assess, prioritize and remediate | Gate on fixable HIGH/CRITICAL; reviewed OpenVEX statements for exceptions |
| RV.3 Analyze root causes | Defects traced to upstream are reported upstream |

## SLSA

- **Build provenance:** GitHub artifact attestations generated in a reusable
  workflow (`build.yml`). Verifying with `--signer-workflow` pins provenance
  to that workflow, which is GitHub's documented pattern for SLSA v1.0
  Build Level 3.
- **Not claimed:** hermetic or reproducible builds. Timestamps are normalized
  (`SOURCE_DATE_EPOCH`, `rewrite-timestamp`), but Alpine packages are fetched
  at build time.
- **SBOM, vulnerability and VEX attestations** are signed by the release
  workflow, not inside the isolated build, so they carry Build Level 2 trust.
