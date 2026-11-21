# Verification record — pihole-hardened

This is a dated log. Each section records what was tested on its date and is
not rewritten afterwards, so earlier sections describe earlier versions. Where
a later section supersedes an earlier statement, the earlier one says so.

**Current state (2026-11-21):** pins are docker-pi-hole 2026.11.0, FTL v6.9,
Core v6.6, Web v6.6.1 on Alpine 3.24.3. The smoke test has 13 checks. `sudo`
is no longer in the image. One release has been published from GitHub,
`2026.10.1-h1`, from an earlier commit; see the last section.

## Initial verification (2026-11-08)

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
| `sudo` removed | `gravity.sh` re-execs via `sudo -u pihole` (true for Core v6.5; Core v6.6 uses `setpriv`, and `sudo` left the image on 2026-11-19) | gravity update fails |
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

`scripts/smoke-test.sh` covered, on this date: health, DNS, FTL running as `pihole`, API
login, gravity update (cron path), log rotation, update checker, no setuid/apk,
clean shutdown (12 checks after the review of the same day, 13 since 2026-11-20). Gravity is exercised for permissions and DB swap; list
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
- arm64 / arm/v7 runtime (arm64 has since run on GitHub: smoke test in CI and the lab in the first release, see the last section; arm/v7 is built and scanned but never run)
- DHCP across a physical LAN (the lab proves the server on a Docker bridge)
- release, signing, attestation and compliance-bundle workflows (since run, see the last section)
- Test-environment differences: the subject image's base had this sandbox's
  proxy CA appended to its trust store (needed to build here; irrelevant on
  the offline lab network), and the control image came from the
  `mirror.gcr.io` Docker Hub mirror because Docker Hub rate-limited the sandbox.

## Pipeline validation (2026-11-08)

On this date the workflows had not run on GitHub (they have since; see the
last section). Everything that could be checked locally was:

| Check | Result |
|---|---|
| actionlint 1.7.12, zizmor 1.32.0 (default and pedantic), shellcheck | clean |
| Renovate config (`renovate-config-validator --strict`) | valid; regex managers find all 7 tracked versions |
| Action versions | resolved to commit SHAs from their release tags; inputs checked against each `action.yml` |
| `scripts/scan-image.sh` | hardened image: 0 findings; official image: same 5 findings as above (empty VEX hides nothing) |
| SBOMs after adding Pi-hole components | SPDX 2.3 valid (spdx-tools), CycloneDX 1.6 valid (strict schema); FTL SHA-256 matches the binary in the image |
| `scripts/build-compliance-bundle.sh` | 15-file bundle from real scan and lab output for one platform; `SHA256SUMS` verifies (the first three-platform release lists 28 files) |
| Re-tagging with `buildx imagetools create` | index digest unchanged, with and without annotations (local registry), so signatures stay valid |
| `deploy/update.sh` | first install, upgrade, no-op, and automatic rollback from an unhealthy image (DNS back within 19 s) |

Found and fixed during this check:

- Trivy's SBOMs omitted Pi-hole itself (FTL, Core, Web). `scripts/sbom-add-pihole.py`
  now adds them, with versions, commits and the FTL hash. (FTL's statically
  linked libraries and the bundled JavaScript were added on 2026-11-20; see
  the last section.)
- zizmor fails CI on `uses: ./…` for reusable workflows (it now prefers
  GitHub's `$/` syntax, which actionlint 1.7.12 rejects). Suppressed inline with
  a reason.

Not verified on this date: GHCR push and package creation,
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

`deploy/docker-compose.dockerhub.yml` (the self-contained Docker Hub compose
file) was started as-is with only `PIHOLE_IMAGE` pointed at the local build:
healthy, DNS answers on the published port 53, the UI answers on
127.0.0.1:8443, API login works with the secret-file password, and the
container has the 7 capabilities and `no-new-privileges`.
`scripts/check-compose-parity.sh` passes, and fails when one setting is changed
in only one of the two files.

## Re-validation on upstream 2026.11.0 (2026-11-19)

The pins moved to docker-pi-hole 2026.11.0, FTL v6.9 and Core v6.6 (Web
v6.6.1 unchanged), `sudo` left the image (upstream now drops privileges with
`setpriv`), and `scripts/patch-upstream.sh` closes two root-writes-through-a-
`pihole`-owned-path cases in upstream's container scripts. Findings and method:
[SECURITY-REVIEW-2026-11-19.md](SECURITY-REVIEW-2026-11-19.md).

| Check | Result |
|---|---|
| `scripts/smoke-test.sh` | PASS, 12 checks, including the new one: symlinks planted as the `pihole` user, every job in root's crontab run as crond runs it, restart; root wrote through none of them. The same test **fails** on a build without the patch. |
| Functional parity lab vs. `pihole/pihole:2026.11.0` | **PASS**: core 40/40 on both images, 40/40 identical; posture 7/7; variants 9/9 ([LAB-REPORT-2026-11-20.md](LAB-REPORT-2026-11-20.md)) |
| Image comparison (Trivy 0.69.3) | official: 94 packages, 147 MB, 11 findings (MEDIUM, fixable: OpenSSL, zlib), 7 setuid files; hardened: 83 packages, 118 MB, 0 findings, 0 setuid files |
| Package drift check | 20 upstream packages, 16 here; only `tini` added |
| Linters | hadolint, actionlint, zizmor (pedantic), shellcheck, `trivy config`: clean |

The numbers in the sections above are from 2026-11-08 and upstream 2026.10.1.
The first table's 2026-11-08 comparison (93 and 84 packages, 148.8 and
112.5 MB, 5 findings) is likewise for 2026.10.1.
One caution from this run: an image built from an 11-day-old local layer
cache scanned with 31 findings, because the cached `apk upgrade` layer
predated new krb5 and OpenSSL fixes. A build without the cache scanned clean.
The GitHub workflows don't use a layer cache.

## 2026-11-20: web application and network service review

Method, findings and what remains untested:
[SECURITY-REVIEW-2026-11-20.md](SECURITY-REVIEW-2026-11-20.md). The scripts
are in `lab/security/`.

| Check | Result |
|---|---|
| Web interface and API after login, sessions, 2FA, Teleporter, TLS | No authentication bypass, script injection or code execution. Nine lower-severity upstream weaknesses, reported privately |
| DNS, DHCP, NTP and web port under hostile traffic | No crash or restart; amplification at most 2.8x; rate limits work; web port can be held busy by slow connections (DNS unaffected) |
| FTL v6.9 built with AddressSanitizer and UndefinedBehaviorSanitizer | 119,680 malformed DNS packets, 60,000 malformed NTP packets, 10,000 hostile API requests, 400 mutated Teleporter uploads: no sanitizer report |
| OWASP ZAP (baseline and authenticated API scan), nuclei (12,323 templates), nikto | Nothing above low severity; details in the review |
| Embedded libraries and bundled JavaScript | Now in both SBOM formats (33 components) and scanned at every release; 7 CVE IDs match, triaged in `vex/EMBEDDED-TRIAGE.md` |
| `scripts/smoke-test.sh` after the changes | PASS, 13 checks. New: the API refuses web-root and dnsmasq-line changes and answers no configuration read without a session |
| `scripts/scan-image.sh` and `scripts/build-compliance-bundle.sh` on the rebuilt image | 0 findings in the gating scan; embedded scan and triage appear in `vulnerability-report.md`; SBOMs validate (SPDX 2.3, CycloneDX 1.6 strict) |
| New compose settings | `webserver.session.restore=false`: no session rows on disk, old session refused after a restart. `dns.dnssec` and `stop-dns-rebind` accepted by FTL when enabled |

Not done here: coverage-guided fuzzing, the TLS path under sanitizers, IPv6
and DHCPv6, ARM at runtime, a physical LAN.

## First release on GitHub (2026-11-21)

`benheise/pihole-hardened` published `2026.10.1-h1`
(`ghcr.io/benheise/pihole-hardened@sha256:d446108c…b8ae`, workflow run
44865449594, commit `9db3cdc`). This is the first time the workflows ran on
GitHub. Read from the published release assets:

| Item | Result |
|---|---|
| Build | amd64, arm64 and arm/v7 images under one index; per-platform digests and FTL hashes in `image-digests.json` |
| Scan gates | Trivy 0.69.3 and Grype: 0 findings on all three platforms |
| Lab on GitHub's amd64 runner | PASS: core 40/40, parity 40/40, posture 7/7, variants 7 pass and 2 skipped (V07, V08: "host port 53 in use", as predicted) |
| Lab on GitHub's arm64 runner | PASS with the same numbers. First runtime test on ARM hardware |
| Bundle | 28 files listed in `SHA256SUMS`, plus `SHA256SUMS.sigstore.json`; the seven files downloaded for this check match their checksums |
| Time from push to release | about 20 minutes |

What this does and does not confirm:

- That commit predates the 2026-11-19 and 2026-11-20 changes. The release was
  built from upstream 2026.10.1, FTL v6.8 and Core v6.5. It does not contain
  `scripts/patch-upstream.sh` (the two root-write fixes), the 13th smoke-test
  check, the embedded-component SBOM entries or the session setting. Those
  ship with the next release from the current tree.
- The signatures and attestations were not verified for this record: the
  environment it was written in cannot reach Sigstore. Run
  `scripts/verify-release.sh benheise/pihole-hardened latest` on a machine
  with cosign 3.x to check them.
- Still not exercised on GitHub: the Docker Hub copy, the drift gate against
  a previous release (the first release has nothing to compare with), the
  embedded-component scan step, Renovate, and the Pi-side updater.
- Deployment through Portainer needed absolute paths in place of
  `./webpassword` and `./etc-pihole` and a literal image reference; the README
  and the compose files now say so.
