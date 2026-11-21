# pihole-hardened

A hardened rebuild of the official [Pi-hole Docker image](https://github.com/pi-hole/docker-pi-hole) for Raspberry Pi (arm64, armv7) and amd64. GitHub Actions builds, tests, signs and publishes it with no manual steps, and each release ships with a compliance bundle: SBOMs, vulnerability reports, VEX, SLSA provenance and lab test results.

It stays close to upstream on purpose. It uses the same Alpine base, the same FTL, Core and Web releases, and upstream's own startup scripts. The hardening comes from what's removed, how the container runs, and how the image is delivered.

## What's different from the official image

| | Official `pihole/pihole` | This image |
|---|---|---|
| Build inputs | Latest FTL/Core/Web fetched at build time | Exact versions pinned in `upstream.env`; FTL binary checked against its published checksum; every release records what each tag resolved to, and the next release refuses to ship if a tag moved |
| Contents | Includes git, binutils, wget, unzip, apk; repository metadata in the web root | Build-only tools and the package manager removed; base packages upgraded at build; `.github`, `.devcontainer`, `package-lock.json` and other repository files removed from the web root (FTL serves them before login) |
| setuid/setgid binaries | 8 | 0 |
| Runtime privileges | Docker's 14 default capabilities; NTP server on 123/udp | 7 capabilities, `no-new-privileges`; FTL runs as a dedicated UID with no effective capabilities; NTP off; admin password from a Docker secret, not the environment |
| Delivery | Tags on Docker Hub | Signed index on GHCR and, optionally, the identical index on Docker Hub with its signatures and attestations; deployed by digest after verification |

Measured on 2026-11-08 against upstream 2026.10.1:

| | Official | Hardened |
|---|---|---|
| Known vulnerabilities (Trivy) | 5 (4 HIGH, 1 MEDIUM) | 0 |
| OS packages | 93 | 84 |
| Image size (uncompressed, amd64) | 149 MB | 112 MB |
| Functional tests (lab, 40 checks) | 40/40 | 40/40, identical results |

Full test record: [docs/verification/VERIFICATION.md](docs/verification/VERIFICATION.md). Security review of this repository's own code and configuration: [docs/verification/SECURITY-REVIEW-2026-11-08.md](docs/verification/SECURITY-REVIEW-2026-11-08.md).

## Deploy on a Raspberry Pi

Prerequisites on the Pi: Docker with Compose v2, plus `cosign` 3.x, `curl` and `jq`. Port 53 must be free; on Debian or Ubuntu hosts, set `DNSStubListener=no` in `/etc/systemd/resolved.conf`.

```sh
sudo mkdir -p /opt/pihole && cd /opt/pihole
REPO=benheise/pihole-hardened   # this repository
# copy deploy/docker-compose.yml, deploy/update.sh and scripts/verify-release.sh here
openssl rand -base64 24 | sudo tee webpassword >/dev/null   # admin password, mounted as a Docker secret
sudo chmod 600 webpassword
sudo REPO=$REPO ./update.sh        # verifies the latest release, writes .env, starts Pi-hole
```

To update automatically, install `deploy/pihole-update.service` and `deploy/pihole-update.timer`: set `REPO=` in the service, then run `systemctl enable --now pihole-update.timer`. Each run verifies the newest release and switches to its digest. If the new container isn't healthy within five minutes, it rolls back. It refuses to move to an older release than the one running (`ALLOW_DOWNGRADE=1` overrides), since a re-published old release would still carry valid signatures. DNS is briefly unavailable during a switch, so the timer runs at 04:30.

DHCP needs extra capabilities and host networking; see the comments at the end of `deploy/docker-compose.yml`.

## Verify a release yourself

```sh
scripts/verify-release.sh benheise/pihole-hardened latest
```

This checks the signed checksum manifest, the image signature, and the SBOM, vulnerability and VEX attestations on every platform. If `gh` is installed and logged in, it also checks SLSA provenance. Manual commands are in each release's `VERIFY.md`.

## How the pipeline works

```
Renovate PR (upstream bump, base digest, action SHA)
  └─ ci.yml: lint, package drift check, build + smoke test on amd64 and arm64, vulnerability gate
       └─ auto-merge to main
            └─ release.yml (also weekly, to pick up Alpine fixes)
                 ├─ build.yml (reusable): amd64, arm64 native; armv7 emulated
                 │    └─ one index → SLSA provenance + keyless signature
                 ├─ scan × 3 platforms: Trivy + Grype gates → signed SBOM, vuln, VEX attestations
                 ├─ lab × 2 (amd64, arm64): official vs. hardened image, same tests
                 └─ publish: upstream drift gate → GHCR tags (+ identical signed copy on
                      Docker Hub, if configured) → compliance bundle, signed SHA256SUMS, release
                 (any failure: nothing is published; an issue is opened)
```

One step is deliberately left to a person: adding a VEX statement to accept a vulnerability that doesn't apply. That change goes through a reviewed pull request.

## What each release contains

| File | Purpose |
|---|---|
| `image-digests.json` | Index and per-platform digests, upstream versions with the commits and FTL hashes they resolved to, source commit |
| `build-inputs-*.txt` | The build's own record of every upstream input, copied out of the image |
| `sbom-*.spdx.json`, `sbom-*.cdx.json` | SBOMs (SPDX and CycloneDX), one per platform |
| `vulnerabilities-*` | Trivy JSON and SARIF, Grype JSON, per platform |
| `vulnerability-report.md` | Human-readable summary |
| `vex.openvex.json` | Exploitability statements applied to the scan |
| `provenance.sigstore.jsonl` | SLSA build provenance (Sigstore bundle) |
| `lab-report-*.md` | Functional parity lab results, amd64 and arm64 |
| `licenses.csv` | Component license inventory |
| `control-mapping.md` | CMMC Level 1, NIST SP 800-190, SSDF and SLSA mapping |
| `VERIFY.md`, `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Verification instructions and signed checksums |

These are evidence for an assessment, not a compliance determination. This system is not authorized for CUI.

## Repository layout

```
Dockerfile             hardened image (multi-stage, pinned inputs)
upstream.env           upstream versions (Renovate-managed)
.github/workflows/     ci, build (reusable), release, scorecard
scripts/               scanning, smoke test, package and tag drift, bundle, Docker Hub copy, verification
lab/                   functional parity lab (lab/LAB-PLAN.md)
deploy/                compose file, update script, systemd units
compliance/            control mapping
vex/                   OpenVEX statements
docs/                  setup walkthrough, verification record
```

Setting up your own copy of this pipeline: [docs/SETUP.md](docs/SETUP.md). Publishing to Docker Hub as well is step 7 there; it is off until you set one repository variable.

## Running the lab

```sh
lab/run-lab.sh            # about 15 minutes; writes lab/results/LAB-REPORT.md
```

The lab runs the official image and this image side by side on an isolated network, with a local DNS zone and blocklists, and compares 40 functional checks, 7 runtime posture checks and 9 deployment scenarios. Details: [lab/LAB-PLAN.md](lab/LAB-PLAN.md).

## License

EUPL-1.2, the same licence as Pi-hole. See [LICENSE](LICENSE). Pi-hole is a registered trademark of Pi-hole LLC. This project is not affiliated with or endorsed by Pi-hole.
