# Lab report — hardened Pi-hole vs. official image

- **Run:** 2026-11-20T00:04:29Z on Docker 29.9.2 (amd64)
- **Control:** `pihole/pihole:2026.11.0` (`sha256:66c798d79a95`)
- **Subject:** `pihole-hardened:ci` (`sha256:7aec78886b53`)
- **Plan:** `lab/LAB-PLAN.md`; raw results: `*.jsonl` in this folder

## Verdict

**PASS** — the hardened image keeps every tested capability of the official image and meets every hardening check.

| Area | Result |
|---|---|
| Core capabilities (subject) | 40/40 pass |
| Parity with control | 40/40 identical |
| Runtime posture (subject) | 7/7 pass |
| Variant scenarios | 9 pass, 0 fail, 0 skipped |

## Core capabilities

| ID | Capability | Control | Subject | Same? | Subject detail |
|---|---|---|---|---|---|
| B01 | Gravity: domain list | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B02 | Domain list is exact-match | ✅ PASS | ✅ PASS | ✓ | 10.10.0.95 |
| B03 | Gravity: hosts format | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B04 | Gravity: ABP format | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B05 | ABP covers subdomains | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B06 | Blocked AAAA | ✅ PASS | ✅ PASS | ✓ | :: |
| B07 | Exact denylist | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B08 | Regex denylist | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 0.0.0.0 |
| B09 | Exact allowlist beats gravity | ✅ PASS | ✅ PASS | ✓ | 10.10.0.81 |
| B10 | Allow-type list beats gravity | ✅ PASS | ✅ PASS | ✓ | 10.10.0.96 |
| B11 | CNAME deep inspection | ✅ PASS | ✅ PASS | ✓ | 0.0.0.0 |
| B12 | Query log status codes | ✅ PASS | ✅ PASS | ✓ | GRAVITY DENYLIST REGEX GRAVITY_CNAME FORWARDED CACHE |
| B13 | Per-group policy (a blocked, b not) | ✅ PASS | ✅ PASS | ✓ | a=0.0.0.0 b=10.10.0.66 |
| B14 | Timed disable / re-enable | ✅ PASS | ✅ PASS | ✓ | during=10.10.0.66 after=0.0.0.0 |
| B15 | Search API | ✅ PASS | ✅ PASS | ✓ | http://lists.lab.example/block-domains.txt  |
| B16 | CLI search (pihole -q) | ✅ PASS | ✅ PASS | ✓ | Found 0 domains exactly matching 'ads.lab.example'.  Found 1 lists exactly match |
| B17 | Blocked reply TTL = blockTTL | ✅ PASS | ✅ PASS | ✓ | 2 |
| C01 | Startup (health) | ✅ PASS | ✅ PASS | ✓ | healthy |
| C02 | Self-resolution (pi.hole) | ✅ PASS | ✅ PASS | ✓ | 172.30.0.54 |
| D01 | Forwarding (A) | ✅ PASS | ✅ PASS | ✓ | 10.10.0.1 |
| D02 | Forwarding (AAAA) | ✅ PASS | ✅ PASS | ✓ | fd00::1 |
| D03 | TXT record | ✅ PASS | ✅ PASS | ✓ | "lab-txt-ok" |
| D04 | MX record | ✅ PASS | ✅ PASS | ✓ | 10 mail.lab.example.  |
| D05 | DNS over TCP | ✅ PASS | ✅ PASS | ✓ | 10.10.0.1 |
| D06 | NXDOMAIN passthrough | ✅ PASS | ✅ PASS | ✓ | NXDOMAIN |
| D07 | Caching | ✅ PASS | ✅ PASS | ✓ | second query answered from cache |
| D08 | RFC 6761: .test never forwarded | ✅ PASS | ✅ PASS | ✓ | pihole=NXDOMAIN upstream=10.10.0.99 |
| L01 | Local A record | ✅ PASS | ✅ PASS | ✓ | 10.10.0.50 |
| L02 | Local CNAME record | ✅ PASS | ✅ PASS | ✓ | nas.home.lab. 10.10.0.50  |
| M01 | API auth (good/bad password) | ✅ PASS | ✅ PASS | ✓ | good=200 bad=401 |
| M02 | Web interface (HTTP/HTTPS) | ✅ PASS | ✅ PASS | ✓ | http=200 https=200 |
| M03 | Statistics | ✅ PASS | ✅ PASS | ✓ | total=32 blocked=12 gravity_domains=7 |
| M04 | Gravity via API | ✅ PASS | ✅ PASS | ✓ | lists=4 domains=3 unfiltered_gid=1 gravity_done=1  |
| M05 | Scheduler (crond + jobs) | ✅ PASS | ✅ PASS | ✓ | running 3 |
| M06 | Log rotation | ✅ PASS | ✅ PASS | ✓ | denied=0 rotated=3 |
| M07 | Long-term database writes | ✅ PASS | ✅ PASS | ✓ | rows=29 |
| M08 | Rate limiting | ✅ PASS | ✅ PASS | ✓ |  20 NOERROR  20 REFUSED  |
| M09 | Persistence across restart | ✅ PASS | ✅ PASS | ✓ | healthy lists=4 domains=3 groups=Default,unfiltered 0.0.0.0 0.0.0.0 10.10.0.66 |
| M10 | Teleporter export | ✅ PASS | ✅ PASS | ✓ | 5 files incl. pihole.toml, gravity.db |
| N01 | NTP server | ✅ PASS | ✅ PASS | ✓ | stratum=16 transmit_seconds=4004122031  |

## Measurements (not pass/fail)

| ID | Measure | Control | Subject |
|---|---|---|---|
| X01 | Throughput sanity (500 queries) | ms=792 answered=500 | ms=805 answered=500 |

## Runtime posture

Pass/fail applies to the subject; control values are shown for comparison.

| ID | Check | Control | Subject | Result |
|---|---|---|---|---|
| P01 | pihole-FTL user | `pihole:1000` | `pihole:1999` | ✅ PASS |
| P02 | pihole-FTL effective caps | `0000000000002400` | `0000000000000000` | ✅ PASS |
| P03 | NoNewPrivs (PID 1) | `0` | `1` | ✅ PASS |
| P04 | Bounding capability set | `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,ca` | `cap_chown,cap_dac_override,cap_fowner,cap_kill,cap_setgid,ca` | ✅ PASS |
| P05 | setuid/setgid files | `7` | `0` | ✅ PASS |
| P06 | Package manager present | `yes` | `no` | ✅ PASS |
| P07 | Owner of /etc/pihole data | `1000:1000` | `1999:1999` | ✅ PASS |

## Variant scenarios

| ID | Scenario | Result | Detail |
|---|---|---|---|
| V01 | Migration control -> subject | ✅ PASS | healthy lists=4 domains=3 blocking=[0.0.0.0 0.0.0.0 0.0.0.0] owner=1999:1999 |
| V02 | Rollback subject -> control | ✅ PASS | healthy lists=4 domains=3 blocking=[0.0.0.0 0.0.0.0 0.0.0.0] owner=1000:1000 |
| V03 | Teleporter control -> subject | ✅ PASS | imported=yes lists=4 domains=3 groups=Default,unfiltered blocking=[0.0.0.0 0.0.0.0 0.0.0.0] b-ads=10.10.0.66 n |
| V04 | DHCP (subject, documented settings) | ✅ PASS | healthy lease_in_range=yes in_api=yes |
| V05 | DHCP (control + NET_ADMIN) | ✅ PASS | healthy lease_in_range=yes in_api=yes |
| V06 | DHCP without NET_ADMIN (parity) | ✅ PASS | subject=unhealthy/crit=yes |
| V07 | Host net + no-new-privileges | ✅ PASS | fails as documented: starting answer=none bind_errors=2 |
| V08 | Host net without no-new-privileges | ✅ PASS | healthy answer=127.0.0.1 bind_errors=0 |
| V09 | DHCP + no-new-privileges fails | ✅ PASS | fails as documented: unhealthy, dnsmasq reports missing NET_ADMIN |

## Failures and mismatches

None.
