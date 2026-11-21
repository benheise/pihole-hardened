# Security test harness

The scripts used for the 2026-11-20 review
([docs/verification/SECURITY-REVIEW-2026-11-20.md](../../docs/verification/SECURITY-REVIEW-2026-11-20.md)).
They attack a running Pi-hole the way a LAN device, a logged-in admin, or a
hostile blocklist server would, and report what got through. CI does not run
them: several take the web interface down on purpose, and a full pass takes
about two hours. Re-run them after a Pi-hole version bump that touches the web
server, the API or gravity.

Run them only against a test instance on an isolated Docker network, never
against a Pi-hole that people depend on.

## Test bed

```sh
docker network create --subnet 172.31.50.0/24 sec
# a LAN client that is also the upstream DNS server and the hostile list server
docker run -d --name client --network sec --ip 172.31.50.50 \
  -v "$PWD/lab/security:/t:ro" <an image with python3, dnsmasq and curl> \
  sh -c 'dnsmasq -C /t/client-upstream.conf && python3 /t/evil_http.py'
# the target: the same options as scripts/smoke-test.sh, plus a fixed address,
# the admin password "test" (the scripts assume it) and room for many sessions
docker run -d --name target --network sec --ip 172.31.50.10 \
  -e FTLCONF_webserver_api_password=test -e FTLCONF_webserver_api_max_sessions=200 \
  -e FTLCONF_dns_upstreams=172.31.50.50 \
  -e FTLCONF_dns_revServers=true,172.31.50.0/24,172.31.50.50,lan \
  ...hardening options... pihole-hardened:ci
```

Run the same tests against `pihole/pihole:<tag>` to tell upstream behaviour
from something this image introduced.

## Scripts

| Script | What it does |
|---|---|
| `dnsq.py` | Sends DNS queries whose names contain markup, quotes and control bytes, so they land in the query log |
| `client-upstream.conf` | dnsmasq configuration for the fake upstream: hostile PTR, CNAME and TXT answers, oversized TXT sets |
| `xss_check.py` | Logs in with a headless browser (Playwright), opens every page that shows stored or DNS-derived data, and reports any payload that ran or became markup |
| `cfg_inject.py` | Tries to smuggle a second line into every string setting through the API and checks the files FTL generates |
| `teleporter_test.py` | Hostile Teleporter imports: path traversal, absolute paths, symlinks, extra files, zip bomb, oversize, truncated, then mutated archives |
| `teleporter_fuzz.py` | Mutated zip and legacy tar.gz uploads only (used against the sanitizer build) |
| `evil_http.py` | Blocklist server that answers with redirects to internal and non-HTTP URLs, huge lines, binary data, a gzip bomb and a stalled response |
| `dns_tests.py` | `ratelimit`, `amplify` (response-to-request size for query types an attacker would pick) and `fuzz` (malformed DNS packets) |
| `fake_upstream.py` | Records the source ports and transaction IDs of FTL's upstream queries (cache-poisoning resistance) |
| `dhcp_ntp.py` | Hostile DHCP hostnames and options, pool exhaustion, malformed DHCP packets; NTP modes, amplification, rate limit, malformed NTP packets |
| `webdos.py` | Slow headers, slow bodies, large bodies and idle-connection floods against the web port, with DNS checked throughout |
| `api_fuzz.py` | Malformed HTTP and hostile parameters and JSON bodies on every API endpoint in `api-endpoints.txt`, with and without a session |
| `ftl-openapi.json` | OpenAPI description generated from FTL's endpoint table, for an authenticated ZAP API scan (FTL's own spec file imports only a handful of URLs) |

## Scanners

```sh
# OWASP ZAP: passive baseline, then an active scan of the API with a session
docker run --rm --network sec -v "$PWD/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://172.31.50.10/admin/login -J baseline.json
SID=$(curl -s -X POST http://172.31.50.10/api/auth -d '{"password":"test"}' | jq -r .session.sid)
cp ftl-openapi.json zap/     # and give the target a long webserver.session.timeout
docker run --rm --network sec -v "$PWD/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t ftl-openapi.json -f openapi -O http://172.31.50.10 -J api.json -T 25 \
  -z "-config replacer.full_list(0).description=sid -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=sid \
      -config replacer.full_list(0).regex=false \
      -config replacer.full_list(0).replacement=$SID"
nuclei -u http://172.31.50.10 -u https://172.31.50.10 -t http,ssl,network,dns
nikto -h http://172.31.50.10
```

ZAP's active scan reports "SQL injection" on many API parameters. It compares
response bodies, and every FTL API response carries a `took` time that differs
between identical requests. Check any such alert by hand before believing it.

## Sanitizer build

Memory-safety testing needs FTL compiled with AddressSanitizer and
UndefinedBehaviorSanitizer, which the release binary is not. Build FTL from
the tag pinned in `upstream.env` with
`-fsanitize=address,undefined -fno-omit-frame-pointer` added to the C flags
(drop `-Werror`), run it with `ASAN_OPTIONS=log_path=...`, and point
`dns_tests.py fuzz` (`DNS_PORT` sets the port), `dhcp_ntp.py ntpfuzz`,
`api_fuzz.py` and `teleporter_fuzz.py` at it. Any report file or
`runtime error` line is a finding. Upstream's own test suite builds its tar,
gzip and DNS-record parsers under the same sanitizers.
