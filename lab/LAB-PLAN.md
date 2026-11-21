# Container lab plan — hardened Pi-hole functional and security parity

**Question the lab answers:** does the hardened image, run with the production
hardening settings, still do everything the official image does (blocking,
DNS, local records, management, maintenance, persistence, DHCP), and do the
hardening controls actually hold at runtime?

**Method:** run the official image (**control**) and the hardened image
(**subject**) side by side in an isolated Docker network, put both through the
same scripted test suite, and compare. A test passes when the subject meets the
expected result; parity is reported separately so any behavior difference from
upstream is visible even when both "pass".

| Role | Image | Runtime settings |
|---|---|---|
| control | `pihole/pihole:<tag pinned in upstream.env>` (`CONTROL_IMAGE` overrides it) | Docker defaults, as most people run it |
| subject | `pihole-hardened` built from this repo, or the image a release just built (`SUBJECT_IMAGE`) | `deploy/docker-compose.yml` hardening: cap_drop ALL + 7 caps, no-new-privileges, `PIHOLE_UID/GID=1999`, pids/memory limits, `/tmp` tmpfs |

The lab compares features, so both images get the same Pi-hole settings, and
three production settings are left out on purpose: FTL's NTP server stays on
(test N01 needs it), the admin password is set through the environment, and
the dot-file and session settings are not applied. `scripts/smoke-test.sh`
is what runs the image with the production settings.

## Topology

All DNS tests run on one `internal: true` bridge network (no internet), so
every answer is deterministic and nothing depends on public blocklists.

```
                 lab network 172.30.0.0/24 (internal, no egress)
 ┌────────────────────────────────────────────────────────────────────────┐
 │ upstream-dns .10  dnsmasq: authoritative test zone lab.example,        │
 │                   fake github.com / raw.githubusercontent.com          │
 │ lists        .11  python http.server: 3 blocklist formats + allow list │
 │ pihole-control .53   pihole-subject .54   (V01-V03 Pi-holes .57/.58)   │
 │ client-a .21 (default group, filtered)                                 │
 │ client-b .22 (group "unfiltered", no blocklists)                       │
 │ client-c .23 (rate-limit target)        admin .24 (API calls)          │
 └────────────────────────────────────────────────────────────────────────┘
                 dhcp network 172.31.0.0/24 (DHCP variants only)
 ┌────────────────────────────────────────────────────────────────────────┐
 │ DHCP Pi-hole .55     client-dhcp .30 (udhcpc)     admin .24            │
 └────────────────────────────────────────────────────────────────────────┘
 Docker assigns dynamic IPs only from .0/25; DHCP leases come from .200–.220.
```

DHCP needs its own non-internal network: Docker's isolation rules for
internal networks drop packets whose source is outside the subnet, and a DHCP
DISCOVER comes from 0.0.0.0. Nothing in the DHCP variants depends on egress.

Both Pi-holes use `upstream-dns` as their only upstream and as their own
container resolver (gravity's pre-download DNS check needs `github.com` to
resolve). Clients query each Pi-hole by IP, so the Pi-hole sees the real client
address and group assignment works.

## Fixtures

**Test zone (upstream-dns, TTL 300):** `allowed`, `ads`, `tracker1`,
`tracker2`, `denyme`, `allowme`, `antigravity`, `plain-list`, `exact-only`,
`child.exact-only`, `hosts-list`, `abp-parent`, `deep.abp-parent`, `mail`
(each `.lab.example`, each with a distinct 10.10.0.x address),
`cname-to-ad.lab.example` → CNAME `ads.lab.example`, TXT and MX records, an
AAAA record on `allowed`, and NXDOMAIN for anything else under `lab.example`.
The zone uses `.example` because Pi-hole never forwards `.test`, `.invalid`,
`.bind` or `.onion` (RFC 6761; FTL writes `server=/test/`). The upstream also
answers `probe.special.test` so test D08 can confirm that behavior.

**Lists (served over HTTP by `lists`):**

| File | Type | Format | Contains |
|---|---|---|---|
| `block-domains.txt` | block | one domain per line | plain-list, exact-only, allowme, antigravity, ads |
| `block-hosts.txt` | block | hosts file | hosts-list |
| `block-abp.txt` | block | Adblock Plus `\|\|x^` | abp-parent |
| `allow-antigravity.txt` | allow | one domain per line | antigravity |

**Configured through the API:** exact deny `denyme`, regex deny
`^tracker[0-9]+\.lab\.example$`, exact allow `allowme`, group `unfiltered` with
client-b as its only member, local A record `nas.home.lab`, local CNAME
`alias.home.lab → nas.home.lab`.

## Test catalog — core suite (run on control and subject)

| ID | Capability | Method | Expected |
|---|---|---|---|
| C01 | Startup | container health status | `healthy` within 120 s |
| C02 | Self-resolution | `dig pi.hole` | an A record |
| D01 | Forwarding (A) | `dig allowed.lab.example` | 10.10.0.1 |
| D02 | Forwarding (AAAA) | `dig AAAA allowed.lab.example` | fd00::1 |
| D03 | TXT | `dig TXT txt.lab.example` | `lab-txt-ok` |
| D04 | MX | `dig MX lab.example` | `mail.lab.example` |
| D05 | DNS over TCP | `dig +tcp allowed.lab.example` | 10.10.0.1 |
| D06 | NXDOMAIN passthrough | `dig nope.lab.example` | status NXDOMAIN |
| D07 | Caching | repeat a query, read query log | second answer has status `CACHE` |
| D08 | Special-use names (RFC 6761) | `dig probe.special.test` via Pi-hole and directly | Pi-hole NXDOMAIN; upstream would answer 10.10.0.99 |
| B01 | Gravity, domain list | `dig plain-list.lab.example` | 0.0.0.0 |
| B02 | Domain lists match exactly | `dig child.exact-only.lab.example` | real address (not blocked) |
| B03 | Gravity, hosts format | `dig hosts-list.lab.example` | 0.0.0.0 |
| B04 | Gravity, ABP format | `dig abp-parent.lab.example` | 0.0.0.0 |
| B05 | ABP covers subdomains | `dig deep.abp-parent.lab.example` | 0.0.0.0 |
| B06 | Blocked AAAA | `dig AAAA ads.lab.example` | `::` |
| B07 | Exact denylist | `dig denyme.lab.example` | 0.0.0.0 |
| B08 | Regex denylist | `dig tracker1/tracker2.lab.example` | 0.0.0.0 both |
| B09 | Exact allowlist beats gravity | `dig allowme.lab.example` | real address |
| B10 | Allow-type list beats gravity | `dig antigravity.lab.example` | real address |
| B11 | CNAME deep inspection | `dig cname-to-ad.lab.example` | blocked (0.0.0.0) |
| B12 | Query log status codes | `GET /api/queries` | GRAVITY, DENYLIST, REGEX, GRAVITY_CNAME, FORWARDED, CACHE each seen for the right domain |
| B13 | Per-group policy | `ads.lab.example` from client-a and client-b | a: 0.0.0.0, b: 10.10.0.66 |
| B14 | Timed disable | `POST /api/dns/blocking` false for 8 s | resolves while disabled, blocked again after |
| B15 | Search API | `GET /api/search/ads.lab.example` | found in a gravity list |
| B16 | CLI search | `pihole -q ads.lab.example` | prints the list URL |
| B17 | Block reply TTL | TTL of a blocked answer | equals `dns.blockTTL` (2) |
| L01 | Local A record | `dig nas.home.lab` | 10.10.0.50 |
| L02 | Local CNAME | `dig alias.home.lab` | CNAME to nas, 10.10.0.50 |
| M01 | API authentication | right / wrong password | session valid / HTTP 401 |
| M02 | Web interface | `/admin/login` over HTTP and HTTPS | HTTP 200 |
| M03 | Statistics | `GET /api/stats/summary` | queries and blocked counts > 0; gravity domain count matches control |
| M04 | Gravity via API | `POST /api/action/gravity` | completes; lab lists counted |
| M05 | Scheduler | crond running, crontab | running; 3 Pi-hole jobs installed |
| M06 | Log rotation | `pihole flush once` | rotated files, no permission errors |
| M07 | Long-term database | row count in `pihole-FTL.db` | > 0 after `DBinterval` (5 s in lab) |
| M08 | Rate limiting | limit 20/60 s, 40 queries from client-c | later queries `REFUSED` |
| M09 | Persistence | `docker restart`, re-test | lists, domains, groups kept; blocking works |
| M10 | Teleporter export | `GET /api/teleporter` | zip containing `pihole.toml` and `gravity.db` |
| N01 | NTP server | SNTP request to udp/123 | a reply |
| X01 | Throughput sanity | 500 cached queries from one client | recorded for comparison (not pass/fail) |

## Runtime posture (recorded for both; pass criteria apply to subject)

| ID | Check | Subject expected |
|---|---|---|
| P01 | User running pihole-FTL | `pihole` (UID 1999) |
| P02 | pihole-FTL effective capabilities | none |
| P03 | `NoNewPrivs` on PID 1 | 1 |
| P04 | Container bounding capability set | exactly the 7 configured |
| P05 | setuid/setgid files | 0 |
| P06 | Package manager present | no |
| P07 | Host-side owner of `/etc/pihole` data | 1999:1999 |

## Variants (separate runs)

| ID | Scenario | Expected |
|---|---|---|
| V01 | **Migration:** control configures a volume, subject starts on the same volume | config, lists and blocking intact; files re-owned to 1999 |
| V02 | **Rollback:** control starts again on that volume | healthy; blocking intact; files back to 1000 |
| V03 | **Teleporter:** control's export imported into a fresh subject | lists, domains, regex and groups restored; blocking works after gravity |
| V04 | **DHCP (subject), documented settings:** 7 caps + NET_ADMIN + NET_RAW, no-new-privileges removed | client-dhcp gets a lease from .200–.220; lease visible in `/api/dhcp/leases` |
| V05 | **DHCP (control)** with NET_ADMIN | same as V04 (parity) |
| V06 | **DHCP enabled without NET_ADMIN**, control and subject | both images behave the same way (parity) |
| V07 | **Host networking with no-new-privileges** (subject, + NET_BIND_SERVICE) | FTL cannot bind port 53 (confirms the compose warning) |
| V08 | **Host networking without no-new-privileges** (subject, + NET_BIND_SERVICE) | healthy; answers on host 127.0.0.1:53 |
| V09 | **DHCP with no-new-privileges kept** (subject + NET_ADMIN, NET_RAW) | DHCP refused ("missing required capability NET_ADMIN") (confirms the compose warning) |

## Changes after the first run

The first run exposed lab and expectation errors, corrected before the
recorded run. None of them changed the images or the production settings.

| Change | Why |
|---|---|
| Zone moved from `lab.test` to `lab.example`; D08 added | Pi-hole correctly refuses to forward `.test` (RFC 6761), so every forwarded test failed on both images |
| DHCP variants moved to a non-internal network | Docker's internal-network rules dropped the DHCP DISCOVERs (source 0.0.0.0) before Pi-hole saw them, on both images |
| V04 runs without no-new-privileges; V09 added | With it, FTL can't use NET_ADMIN and DHCP is refused. The production compose file already says to drop it for DHCP; the lab now tests that guidance in both directions |
| V06 expectation changed to parity | Reading `start.sh` suggested a graceful fallback; in practice both images stop DNS on a config error (see LAB-REPORT findings) |
| M01 sends no session; M07 polls; V07 parses only addresses | Suite bugs: a valid session makes `/auth` return 200; the first DB write can take more than one interval; dig's error text was read as an answer |

## Pass criteria

- Every core test passes on the subject.
- Every core test result on the subject matches control (parity). Any
  mismatch is a finding even if the subject's result is acceptable.
- Every posture check meets the subject expectation.
- Variants meet their expected results.

## Running it

```
lab/run-lab.sh            # build, run everything, write lab/results/LAB-REPORT.md
lab/run-lab.sh --keep     # leave containers up afterwards for inspection
```

Requirements: Docker Engine with Compose v2, `curl`, `jq`, `python3`, host port
53/80/443 free (V07/V08 only). The runner tears the lab down at the end unless
`--keep` is given. Raw per-test results are written as JSON lines to
`lab/results/` alongside the report.

## Out of scope / known limits

- **CPU architecture:** runs on the host's architecture only. The release
  workflow runs it on amd64 and arm64 runners; 32-bit ARM (arm/v7) is built
  and scanned but not run.
- **Host networking on GitHub's runners:** V07 and V08 are skipped there
  because the runner's own DNS stub holds port 53.
- **Real LAN DHCP:** V04–V06 test the DHCP server on a Docker bridge. They
  prove the server works under the hardened capability set, not reachability
  across a physical LAN.
- **DNSSEC and IPv6 transport:** the lab zone is unsigned and the lab network
  is IPv4-only.
- **Public blocklists and internet upstreams:** deliberately replaced by
  fixtures; list download over HTTPS is exercised only by the CI smoke test.
- **Performance:** X01 is a sanity comparison, not a benchmark.
