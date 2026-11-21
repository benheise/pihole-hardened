# Verification record — pihole-hardened

Tested 2026-11-08 (UTC) against upstream docker-pi-hole **2026.10.1** (FTL v6.8,
Core v6.5, Web v6.6.1, Alpine 3.24.3 digest `be265606…2c9a`).
Environment: Docker Engine 29.9.2, overlayfs, linux/amd64. Containers ran on a
bridge network with a fresh `/etc/pihole` volume per run.

## Upstream Dockerfile vs. the earlier reconstruction

The upstream `src/Dockerfile` was read from a git clone (GitHub's web page and
API were not reachable from the test environment). Corrections it forced:

| Earlier reconstruction | Upstream reality | Effect if left as-is |
|---|---|---|
| `prefix-time.sh` not copied | `start_cron` pipes crond output through it | cron output pipe breaks |
| prestart/poststop templates not installed | `start.sh` runs both on every start | container exits at start |
| `/macvendor.db` not added | `bash_functions.sh` chowns it (ERR trap) | container exits at start |
| `sudo` removed | `gravity.sh` re-execs via `sudo -u pihole` | gravity update fails |
| build-time `setcap … +eip` incl. SYS_TIME/NET_ADMIN | `start.sh` re-applies caps at runtime from what's available | redundant; risk of exec failure if caps absent |
| `USER pihole` (first sketch) | `start.sh` needs root (usermod, crond, setcap, capsh) | container cannot start |
| ENTRYPOINT `start.sh` assumed | confirmed `["start.sh"]`, no init | tini added here deliberately |

## Runtime capability matrix (hardened image)

| Configuration | Result |
|---|---|
| Docker default caps | healthy |
| drop ALL + CHOWN, SETUID, SETGID, NET_BIND_SERVICE + no-new-privileges (earlier compose) | **exits**: setcap needs SETFCAP |
| + SETFCAP, KILL (no file-access caps) | **exits**: root can't read pihole-owned files / chmod pid file |
| + FOWNER, DAC_READ_SEARCH | healthy, **but log rotation fails silently** |
| + FOWNER, DAC_OVERRIDE (final, minus NET_BIND_SERVICE) | healthy, all paths pass |
| final set without KILL | shutdown hangs 30 s, FTL SIGKILLed (exit 137) |
| final set + no-new-privileges (bridge) | healthy; FTL has 0 effective caps, binds :53 via Docker's `ip_unprivileged_port_start=0` |
| final set + read-only rootfs | **exits**: start.sh writes a capability xattr on `/usr/bin/pihole-FTL` |

Final set: `CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, SETFCAP, KILL` (7 of
Docker's 14 defaults), `no-new-privileges`, `PIHOLE_UID/GID=1999`.
The upstream image also passes every runtime check under this set; it fails
only the "no setuid files, no apk" check.

`scripts/smoke-test.sh` covers: health, DNS, FTL running as `pihole`, API
login, gravity update (cron path), log rotation, update checker, no setuid/apk,
clean shutdown. Gravity is exercised for permissions and DB swap; list
downloads depend on network access.

## Image comparison (Trivy 0.69.3, checksum-verified)

| | upstream `pihole/pihole:2026.10.1` | hardened |
|---|---|---|
| OS packages | 93 | 84 |
| Size (uncompressed) | 148.8 MB | 112.5 MB |
| Vulnerabilities | 5 (4 HIGH, 1 MEDIUM), all fixable | 0 |
| setuid/setgid files | present | 0 |
| apk binary | present | absent |

The 4 HIGH findings were `libexpat` (CVE-2026-113351, -115506, -117610,
-118370), pulled in only by `git`. The MEDIUM was `zlib` CVE-2026-4738 in the
base layer, cleared by `apk upgrade` (Alpine 3.24.4 packages were available).
Vulnerability counts depend on the database date; this is a point-in-time
comparison.

## Lint gates
hadolint 2.15.1 (DL3018 ignored with reason), `trivy config` (DS-0002 ignored
with reason and expiry), actionlint 1.7.12, zizmor 1.32.0 (pedantic), and
shellcheck all pass.

## Functional parity lab (`lab/`)

`lab/run-lab.sh` runs the official image (control) and the hardened image
(subject) side by side on an isolated network with a local test zone and
blocklists. Full run 2026-11-08, 14 minutes, verdict **PASS**
(copy: [LAB-REPORT-2026-11-08.md](LAB-REPORT-2026-11-08.md)):

- **Core capabilities:** 40/40 pass on both images, 40/40 identical. Covers
  forwarding (A, AAAA, TXT, MX, TCP), caching, NXDOMAIN, RFC 6761 names,
  gravity in domain/hosts/ABP formats, exact and regex deny, exact and
  list-based allow, CNAME inspection, per-group policy, timed disable, block
  TTL, local A/CNAME records, query-log statuses, search (API and CLI), API
  auth, web UI, statistics, gravity, cron, log rotation, long-term database,
  rate limiting, NTP, Teleporter export and persistence across restart.
- **Runtime posture:** 7/7 on the subject. FTL runs as UID 1999 with no
  effective capabilities, `NoNewPrivs=1`, only the 7 configured
  capabilities, no setuid files and no package manager.
- **Variants:** 9/9.
  - Migration from the official image to the hardened one on the same volume works, and so does rollback.
  - A Teleporter export from the official image restores fully into the hardened one.
  - DHCP works with the documented settings.
  - DHCP and host networking both fail under `no-new-privileges`, exactly as the compose file warns.

Upstream behavior found by the lab (identical on both images): if DHCP is
enabled but the container lacks NET_ADMIN, FTL stops on a config error and
**DNS goes down too**. `start.sh` intends to fall back to "DHCP will not be
started", but it can't change `dhcp.active` when that came from an
`FTLCONF_` variable (read-only), and the fallback never runs when DHCP was
enabled in `pihole.toml`.

## Not tested here
- arm64 / arm/v7 runtime (CI's `ubuntu-24.04-arm` smoke job covers arm64)
- DHCP across a physical LAN (the lab proves the server on a Docker bridge)
- release, signing, attestation and compliance-bundle workflows
- Test-environment differences: the subject image's base had this sandbox's
  proxy CA appended to its trust store (needed to build here; irrelevant on
  the offline lab network), and the control image came from the
  `mirror.gcr.io` Docker Hub mirror because Docker Hub rate-limited the sandbox.

## Pipeline validation (2026-11-08)

The workflows haven't run on GitHub yet; the first release is their real
test. Everything that could be checked locally was:

| Check | Result |
|---|---|
| actionlint 1.7.12, zizmor 1.32.0 (default and pedantic), shellcheck | clean |
| Renovate config (`renovate-config-validator --strict`) | valid; regex managers find all 7 tracked versions |
| Action versions | resolved to commit SHAs from their release tags; inputs checked against each `action.yml` |
| `scripts/scan-image.sh` | hardened image: 0 findings; official image: same 5 findings as above (empty VEX hides nothing) |
| SBOMs after adding Pi-hole components | SPDX 2.3 valid (spdx-tools), CycloneDX 1.6 valid (strict schema); FTL SHA-256 matches the binary in the image |
| `scripts/build-compliance-bundle.sh` | 15-file bundle from real scan and lab output; `SHA256SUMS` verifies |
| Re-tagging with `buildx imagetools create` | index digest unchanged, with and without annotations (local registry), so signatures stay valid |
| `deploy/update.sh` | first install, upgrade, no-op, and automatic rollback from an unhealthy image (DNS back within 19 s) |

Found and fixed during this check:

- Trivy's SBOMs omitted Pi-hole itself (FTL, Core, Web). `scripts/sbom-add-pihole.py`
  now adds them, with versions, commits and the FTL hash. FTL's statically
  linked libraries (dnsmasq, CivetWeb, Lua, SQLite, mbedTLS) are still not
  enumerated.
- zizmor fails CI on `uses: ./…` for reusable workflows (it now prefers
  GitHub's `$/` syntax, which actionlint 1.7.12 rejects). Suppressed inline with
  a reason.

Not verified until the first release runs: GHCR push and package creation,
keyless signing and attestations, `scripts/verify-release.sh` against a real
release, and the lab on GitHub's arm64 runners. On GitHub-hosted runners, lab
variants V07/V08 will be skipped because the runner's DNS stub uses port 53.

## Security review (2026-11-08)

A review of everything this repository ships found 13 items (2 reported to
upstream as PRs, 11 fixed here): repository metadata served before login,
no detection of moved upstream tags, Trivy installer trusting the release's
own checksum, signed downgrades accepted by the updater, unvalidated
`source upstream.env`, the admin password in the container environment, an
NTP listener, versions showing N/A, and smaller items. Findings, fixes and
the re-verification are in
[SECURITY-REVIEW-2026-11-08.md](SECURITY-REVIEW-2026-11-08.md). The smoke
test enforces every runtime fix on each pull request.

## Docker Hub mirror (2026-11-19)

The release workflow can copy each release to Docker Hub
(`scripts/mirror-image.sh`, steps marked "Docker Hub" in `release.yml`).
Tested between two local registries without a referrers API (`registry:2`),
with a two-platform index signed and attested by cosign 3.1.4 in its default
bundle format:

| Copy method | Index digest preserved | Signature verifies on the copy | Platform attestation verifies on the copy |
|---|---|---|---|
| `oras cp -r` (ORAS 1.3.0 and 1.3.6) | yes | yes | yes |
| `docker buildx imagetools create` | yes | no (attachments not copied) | no |
| `cosign copy` (3.1.4) | copy fails ("already exists") | no | no |

`mirror-image.sh` passed in the order the workflow calls it (version tag
first, then the upstream-version and `latest` tags), rejects a malformed
digest or tag, and the mirrored tag pulls with Docker. `install-oras.sh`
installs the pinned release and is a no-op on the second run. The bundle
records the copy in the signed `image-digests.json` (`mirrors`), and
`verify-release.sh` refuses an `IMAGE_REPO` that the release does not name.

Not verified until a release runs with the variables set: the login and push
against the real Docker Hub (the tests used local registries), and whether
Docker Hub serves the copied attachments through its referrers API or the
tag fallback (ORAS and cosign handle both).
