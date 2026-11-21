# pihole-hardened

A hardened rebuild of the official [Pi-hole Docker image](https://github.com/pi-hole/docker-pi-hole) for Raspberry Pi (arm64, armv7) and amd64. GitHub Actions builds, tests, signs and publishes it with no manual steps, and each release ships with a compliance bundle: SBOMs, vulnerability reports, VEX, SLSA provenance and lab test results.

It stays close to upstream on purpose. It starts from the same Alpine base image, with its packages upgraded at build time, and uses unmodified FTL, Core and Web releases. Upstream's startup scripts are used with two lines patched (see *Root-run jobs* below); nothing else in Pi-hole's code is changed. The hardening comes from what's removed, how the container runs, and how the image is delivered.

## What's different from the official image

| | Official `pihole/pihole` | This image |
|---|---|---|
| Build inputs | Latest FTL, Core, Web and PADD fetched at build time | Exact versions pinned in `upstream.env`; FTL binary checked against its published checksum; every release records what each tag resolved to, and the next release refuses to ship if a tag moved |
| Contents | Includes git, binutils, wget, unzip, bash-completion, PADD and apk; repository metadata in the web root | Those tools and the package manager removed (a small stand-in answers the version queries Pi-hole makes to git; `ADDITIONAL_PACKAGES` is not supported); base packages upgraded at build; `tini` added as PID 1; `.github`, `.devcontainer`, `package-lock.json` and other repository files removed from the web root (FTL serves them before login) |
| setuid/setgid binaries | 7 | 0 |
| Root-run jobs | Root's shell opens files in directories owned by the unprivileged `pihole` user (weekly gravity job, list file at start) | `scripts/patch-upstream.sh` changes those two lines at build: the job runs as `pihole` and the file is created with `noclobber`; the smoke test plants symlinks and fails if root writes through them |
| Runtime privileges (as deployed) | Docker's 14 default capabilities; NTP server on 123/udp; admin password usually in the environment | 7 capabilities, `no-new-privileges`; FTL runs as a dedicated UID with no effective capabilities; NTP off; admin password from a Docker secret; login sessions not kept on disk |
| Delivery | Tags on Docker Hub and GHCR | Signed index on GHCR and, optionally, the identical index on Docker Hub with its signatures and attestations; deployed by digest after verification |

The *Runtime privileges* row describes the image run with `deploy/docker-compose.yml`. The image does not enforce those settings by itself: run it with Docker's defaults and it has upstream's runtime privileges.

Measured on 2026-11-19 against upstream 2026.11.0 (amd64; vulnerability counts change with the scanner database, so each release carries its own report):

| | Official | Hardened |
|---|---|---|
| Known vulnerabilities (Trivy) | 11 (all MEDIUM, all fixable) | 0 |
| OS packages | 94 | 83 |
| Image size (uncompressed, amd64) | 147 MB | 118 MB |
| Functional tests (lab, 40 checks) | 40/40 | 40/40, identical results |

Full test record: [docs/verification/VERIFICATION.md](docs/verification/VERIFICATION.md). Security reviews: [2026-11-08](docs/verification/SECURITY-REVIEW-2026-11-08.md) (this repository's own code and configuration), [2026-11-19](docs/verification/SECURITY-REVIEW-2026-11-19.md) (re-validation of the upstream findings and a second pass) and [2026-11-20](docs/verification/SECURITY-REVIEW-2026-11-20.md) (web interface after login, DNS/DHCP/NTP under attack, fuzzing, embedded libraries, dynamic scanners).

## Deploy on a Raspberry Pi

One command sets everything up. From a clone of this repository:

```sh
sudo bash deploy/install.sh
```

Or without cloning, after reading the script:

```sh
curl -fsSLO https://raw.githubusercontent.com/benheise/pihole-hardened/main/deploy/install.sh
sudo bash install.sh --repo benheise/pihole-hardened
```

`deploy/install.sh` asks before each change it makes outside `/opt/pihole`. It:

- checks the machine's own DNS and port 53, and offers to fix a machine that uses itself as its DNS server or has systemd-resolved's stub listener on the port;
- installs what is missing: `curl`, `jq`, `openssl`, `iproute2`, Docker with the compose plugin, and `cosign` 3.x (checked against its published checksums);
- puts the compose file, `update.sh` and `verify-release.sh` in `/opt/pihole`, generates the admin password file, and writes the machine's time zone to `docker-compose.override.yml`;
- checks that the image can be pulled, and offers a registry login if the GHCR package is still private (`docs/SETUP.md` step 5);
- verifies the signed release, pulls it, starts Pi-hole and waits until it is healthy;
- installs the nightly update timer.

If a container named `pihole` already runs on the machine (a Portainer stack, or the official image), the installer replaces it and takes over its data folder and password. The old container is removed only after the new one is healthy, and is put back if it is not. Run with `--yes` to accept every default without questions; `--help` lists the options. Running it again is safe: it keeps the password, the data and the override file.

Afterwards `sudo /opt/pihole/update.sh` updates by hand, and local changes (ports, DHCP, extra settings) belong in `/opt/pihole/docker-compose.override.yml`, which updates never overwrite.

<details>
<summary>Manual setup, if you prefer to do each step yourself</summary>

Prerequisites on the Pi: Docker with Compose v2, plus `cosign` 3.x, `curl` and `jq`. Port 53 must be free; on Debian or Ubuntu hosts, set `DNSStubListener=no` in `/etc/systemd/resolved.conf`. The machine must not depend on its own Pi-hole for DNS, or the first image pull fails.

```sh
sudo mkdir -p /opt/pihole && cd /opt/pihole
# copy deploy/docker-compose.yml, deploy/update.sh and scripts/verify-release.sh here
openssl rand -base64 24 | sudo tee webpassword >/dev/null   # admin password, mounted as a Docker secret
sudo chmod 600 webpassword
sudo REPO=benheise/pihole-hardened ./update.sh   # verifies the latest release, writes .env, starts Pi-hole
```

To update automatically, install `deploy/pihole-update.service` and `deploy/pihole-update.timer`: set `REPO=` in the service, then run `systemctl enable --now pihole-update.timer`.

</details>

**Quick start from Docker Hub.** [deploy/docker-compose.dockerhub.yml](deploy/docker-compose.dockerhub.yml) is self-contained and carries the same hardening: copy that one file to the host as `docker-compose.yml`, write the `webpassword` file as above, and run `docker compose up -d`. It pulls `docker.io/benheise/pihole-hardened:latest`, which trusts the tag and updates only when you run `docker compose pull`. The installer and `update.sh` verify signatures and pin the digest. They pull from GHCR by default; to pull the Docker Hub copy with the same verification, set `IMAGE_REPO=docker.io/benheise/pihole-hardened` for `update.sh` (in `pihole-update.service` for the timer).

The update timer runs `update.sh` every night at about 04:30. Each run verifies the newest release and switches to its digest. If the new container isn't healthy within five minutes, it rolls back. It refuses to move to an older release than the one running (`ALLOW_DOWNGRADE=1` overrides), since a re-published old release would still carry valid signatures. DNS is briefly unavailable during a switch, so the timer runs at 04:30.

DHCP needs extra capabilities and host networking; see the comments at the end of `deploy/docker-compose.yml`.

**Portainer.** The simplest route is the installer: it replaces an existing Portainer stack's container, keeps its data and password, and the nightly timer then handles updates; delete the stack in Portainer afterwards. To keep managing Pi-hole as a Portainer stack instead, the pasted compose file needs three changes, because a stack in Portainer's web editor has no folder of its own: replace `./webpassword` and `./etc-pihole` with absolute paths that exist on the Docker host, and replace the whole `image:` value with `ghcr.io/benheise/pihole-hardened@sha256:...` (or set `PIHOLE_IMAGE` under the stack's environment variables). `update.sh` does not manage a Portainer stack; update it by changing the digest after running `scripts/verify-release.sh`.

**What the installer trusts.** The Pi-hole image itself is verified: signature, signed checksum manifest and attestations, before anything is started. The tools that do the verifying are trusted on first use: `cosign` is downloaded from its GitHub release and checked against the checksum file published beside it (which proves the download is intact, not who made it); Docker, when missing, is installed by Docker's own script from `get.docker.com`; and when the installer runs without a clone, the compose file and the two scripts come from this repository over HTTPS at the latest release tag. If that is more trust than you want to extend, install Docker and cosign from sources you have verified and run the installer from a clone you have reviewed; it only installs what is missing. A registry token entered for a private package is stored in `/opt/pihole/.docker`, readable by root only.

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
                 │    └─ embedded libraries scanned from the SBOM (reported, not a gate)
                 ├─ lab × 2 (amd64, arm64): official vs. hardened image, same tests
                 └─ publish: upstream drift gate → GHCR tags (+ identical signed copy on
                      Docker Hub, if configured) → compliance bundle, signed SHA256SUMS, release
                 (any failure: nothing is published; an issue is opened)
```

The release workflow runs on every change to `main` that touches the image, pins, scripts, lab or workflows, and every Monday. Changes to documentation or `deploy/` alone do not start a release.

Three things are deliberately left to a person, each through a reviewed pull request: adding a VEX statement to accept a vulnerability that doesn't apply; updating the pinned Trivy and ORAS download hashes when Renovate proposes a new version; and updating `vex/EMBEDDED-TRIAGE.md` when a release reports a CVE in an embedded library that isn't triaged yet.

## What each release contains

| File | Purpose |
|---|---|
| `image-digests.json` | Index and per-platform digests, upstream versions with the commits and FTL hashes they resolved to, source commit |
| `build-inputs-*.txt` | The build's own record of every upstream input, copied out of the image |
| `sbom-*.spdx.json`, `sbom-*.cdx.json` | SBOMs (SPDX and CycloneDX), one per platform: Alpine packages, the Pi-hole components, the libraries compiled into `pihole-FTL` and the JavaScript bundled with the web interface |
| `vulnerabilities-*` | Trivy JSON and SARIF, Grype JSON, per platform; `vulnerabilities-embedded-*` are the informational scans of the embedded libraries |
| `vulnerability-report.md` | Human-readable summary, including known CVEs in the embedded libraries and what each means here |
| `vex.openvex.json` | Exploitability statements applied to the gating scan |
| `provenance.sigstore.jsonl` | SLSA build provenance (Sigstore bundle) |
| `lab-report-*.md` | Functional parity lab results, amd64 and arm64 |
| `licenses.csv` | Component license inventory |
| `control-mapping.md` | CMMC Level 1, NIST SP 800-190, SSDF and SLSA mapping |
| `RELEASE-NOTES.md` | The release description: digest, upstream versions, scan and lab summary |
| `VERIFY.md`, `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Verification instructions and signed checksums |

These are evidence for an assessment, not a compliance determination. This system is not authorized for CUI.

## Repository layout

```
Dockerfile             hardened image (multi-stage, pinned inputs)
upstream.env           upstream versions and tool pins (Renovate-managed)
.github/workflows/     ci, build (reusable), release, scorecard
scripts/               scanning, SBOM completion, smoke test, package and tag drift, bundle, Docker Hub copy, verification
lab/                   functional parity lab (lab/LAB-PLAN.md); security test scripts (lab/security/)
deploy/                installer, compose files (GHCR by digest, Docker Hub by tag), update script, systemd units
compliance/            control mapping
vex/                   OpenVEX statements; triage of CVEs in embedded libraries
docs/                  setup walkthrough (SETUP.md); test record, lab reports and security reviews (verification/)
SECURITY.md            how to report a vulnerability
```

Setting up your own copy of this pipeline: [docs/SETUP.md](docs/SETUP.md). Publishing to Docker Hub as well is step 7 there; it is off until you set one repository variable.

## Running the lab

```sh
lab/run-lab.sh            # about 15 minutes; writes lab/results/LAB-REPORT.md
```

The lab runs the official image and this image side by side on an isolated network, with a local DNS zone and blocklists, and compares 40 functional checks, 7 runtime posture checks and 9 deployment scenarios. Details: [lab/LAB-PLAN.md](lab/LAB-PLAN.md).

## License

EUPL-1.2, the same licence as Pi-hole. See [LICENSE](LICENSE). Pi-hole is a registered trademark of Pi-hole LLC. This project is not affiliated with or endorsed by Pi-hole.
