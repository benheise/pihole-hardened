#!/usr/bin/env bash
# Core suite from LAB-PLAN.md. usage: core.sh <label> <pihole-ip> <container>
# shellcheck disable=SC2319  # "$?" after a test is the intended pass/fail input to expect_true
set -uo pipefail
LABEL=$1 PI=$2 CT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
RES="$HERE/../results/$LABEL.jsonl"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
: >"$RES"
echo "== core suite: $LABEL ($CT @ $PI)"

# ---- startup ----
st=$(wait_healthy "$CT" 150)
expect_eq C01 "Startup (health)" "$st" healthy
[ "$st" = healthy ] || { echo "  aborting: container not healthy"; docker logs "$CT" 2>&1 | tail -30; exit 1; }
a=$(dq client-a pi.hole)
[ -n "$a" ] && expect_true C02 "Self-resolution (pi.hole)" 0 "$a" || expect_true C02 "Self-resolution (pi.hole)" 1 "no answer"

# ---- configuration through the API ----
summary=$(setup_pihole)
echo "  setup: $summary"
login

# ---- forwarding ----
expect_eq D01 "Forwarding (A)" "$(dq client-a allowed.lab.example)" 10.10.0.1
expect_eq D02 "Forwarding (AAAA)" "$(dq client-a allowed.lab.example AAAA)" fd00::1
expect_eq D03 "TXT record" "$(dq client-a txt.lab.example TXT)" '"lab-txt-ok"'
expect_contains D04 "MX record" "$(dq client-a lab.example MX)" mail.lab.example
expect_eq D05 "DNS over TCP" "$(dq client-a allowed.lab.example +tcp)" 10.10.0.1
expect_eq D06 "NXDOMAIN passthrough" "$(dstatus client-a nope.lab.example)" NXDOMAIN
direct=$(docker exec lab-client-a dig +short +time=2 +tries=1 @172.30.0.10 probe.special.test)
expect_eq D08 "RFC 6761: .test never forwarded" "pihole=$(dstatus client-a probe.special.test) upstream=$direct" "pihole=NXDOMAIN upstream=10.10.0.99"
dq client-a allowed.lab.example >/dev/null # second identical query: should come from cache

# ---- blocking ----
expect_eq B01 "Gravity: domain list" "$(dq client-a plain-list.lab.example)" 0.0.0.0
expect_eq B02 "Domain list is exact-match" "$(dq client-a child.exact-only.lab.example)" 10.10.0.95
expect_eq B03 "Gravity: hosts format" "$(dq client-a hosts-list.lab.example)" 0.0.0.0
expect_eq B04 "Gravity: ABP format" "$(dq client-a abp-parent.lab.example)" 0.0.0.0
expect_eq B05 "ABP covers subdomains" "$(dq client-a deep.abp-parent.lab.example)" 0.0.0.0
expect_eq B06 "Blocked AAAA" "$(dq client-a ads.lab.example AAAA)" ::
expect_eq B07 "Exact denylist" "$(dq client-a denyme.lab.example)" 0.0.0.0
t1=$(dq client-a tracker1.lab.example); t2=$(dq client-a tracker2.lab.example)
expect_eq B08 "Regex denylist" "$t1 $t2" "0.0.0.0 0.0.0.0"
expect_eq B09 "Exact allowlist beats gravity" "$(dq client-a allowme.lab.example)" 10.10.0.81
expect_eq B10 "Allow-type list beats gravity" "$(dq client-a antigravity.lab.example)" 10.10.0.96
expect_eq B11 "CNAME deep inspection" "$(dq client-a cname-to-ad.lab.example | tail -1)" 0.0.0.0
a=$(dq client-a ads.lab.example); b=$(dq client-b ads.lab.example)
expect_eq B13 "Per-group policy (a blocked, b not)" "a=$a b=$b" "a=0.0.0.0 b=10.10.0.66"
expect_eq B17 "Blocked reply TTL = blockTTL" "$(dttl client-a plain-list.lab.example)" 2

# ---- local DNS records ----
expect_eq L01 "Local A record" "$(dq client-a nas.home.lab)" 10.10.0.50
expect_contains L02 "Local CNAME record" "$(dq client-a alias.home.lab)" 10.10.0.50

# ---- query log statuses ----
sleep 2
log=$(api GET '/queries?length=1000' | jq -r '.queries[] | "\(.domain) \(.status)"' | sort -u)
missing=""
for pair in "plain-list.lab.example GRAVITY" "denyme.lab.example DENYLIST" "tracker1.lab.example REGEX" \
            "cname-to-ad.lab.example GRAVITY_CNAME" "allowed.lab.example FORWARDED" "allowed.lab.example CACHE"; do
  grep -qxF "$pair" <<<"$log" || missing+="[$pair] "
done
[ -z "$missing" ] && record B12 "Query log status codes" PASS "GRAVITY DENYLIST REGEX GRAVITY_CNAME FORWARDED CACHE" \
                  || record B12 "Query log status codes" FAIL "missing: $missing"
expect_true D07 "Caching" "$(grep -qxF 'allowed.lab.example CACHE' <<<"$log"; echo $?)" "second query answered from cache"

# ---- timed disable ----
api POST /dns/blocking '{"blocking":false,"timer":8}' >/dev/null
sleep 1; during=$(dq client-a ads.lab.example)
sleep 10; after=$(dq client-a ads.lab.example)
expect_eq B14 "Timed disable / re-enable" "during=$during after=$after" "during=10.10.0.66 after=0.0.0.0"

# ---- search ----
s=$(api GET /search/ads.lab.example | jq -r '[.search.gravity[]?.address] | join(" ")')
expect_contains B15 "Search API" "$s" block-domains.txt
expect_contains B16 "CLI search (pihole -q)" "$(docker exec "$CT" pihole -q ads.lab.example 2>&1)" block-domains.txt

# ---- management ----
# No session header here: with a valid session, /auth returns 200 regardless
c_ok=$(SID="" api_code POST /auth "{\"password\":\"$LAB_PASSWORD\"}")
c_bad=$(SID="" api_code POST /auth '{"password":"wrong"}')
expect_eq M01 "API auth (good/bad password)" "good=$c_ok bad=$c_bad" "good=200 bad=401"
h=$(docker exec "$ADMIN" curl -s -o /dev/null -w '%{http_code}' "http://$PI/admin/login")
hs=$(docker exec "$ADMIN" curl -sk -o /dev/null -w '%{http_code}' "https://$PI/admin/login")
expect_eq M02 "Web interface (HTTP/HTTPS)" "http=$h https=$hs" "http=200 https=200"
login
sum=$(api GET /stats/summary)
tot=$(jq -r '.queries.total' <<<"$sum"); blk=$(jq -r '.queries.blocked' <<<"$sum"); grav=$(jq -r '.gravity.domains_being_blocked' <<<"$sum")
[ "$tot" -gt 0 ] 2>/dev/null && [ "$blk" -gt 0 ] 2>/dev/null
expect_true M03 "Statistics" $? "total=$tot blocked=$blk gravity_domains=$grav"
expect_contains M04 "Gravity via API" "$summary" "lists=4 domains=3"
cron=$(docker exec "$CT" sh -c 'pgrep -x crond >/dev/null && echo running; crontab -l 2>/dev/null | grep -c "pihole"')
expect_eq M05 "Scheduler (crond + jobs)" "$(tr '\n' ' ' <<<"$cron" | xargs)" "running 3"
fl=$(docker exec "$CT" pihole flush once quiet 2>&1 | grep -c 'Permission denied')
rot=$(docker exec "$CT" sh -c 'ls /var/log/pihole/*.1 2>/dev/null | wc -l')
expect_eq M06 "Log rotation" "denied=$fl rotated=$rot" "denied=0 rotated=3"
for _ in $(seq 15); do # DBinterval is 5 s in the lab; allow a few cycles
  rows=$(docker exec "$CT" pihole-FTL sqlite3 -ni /etc/pihole/pihole-FTL.db 'SELECT COUNT(*) FROM query_storage;' 2>&1)
  [ "$rows" -gt 0 ] 2>/dev/null && break; sleep 2
done
[ "$rows" -gt 0 ] 2>/dev/null; expect_true M07 "Long-term database writes" $? "rows=$rows"
ntp=$(docker exec lab-client-a python3 /usr/local/bin/sntp.py "$PI" 2>&1)
expect_contains N01 "NTP server" "$ntp" stratum=

# ---- throughput sanity (cached answers, one client) ----
ms=$(docker exec lab-client-b sh -c "for i in \$(seq 500); do echo allowed.lab.example A; done >/tmp/q
  now() { python3 -c 'import time; print(time.monotonic_ns() // 1000000)'; }
  s=\$(now); dig @$PI -f /tmp/q +short +tries=1 +time=2 >/tmp/o; e=\$(now)
  echo \$((e - s)) \$(grep -c '^10.10.0.1\$' /tmp/o)")
record X01 "Throughput sanity (500 queries)" INFO "ms=${ms% *} answered=${ms#* }"

# ---- rate limiting (client-c only) ----
api PATCH /config '{"config":{"dns":{"rateLimit":{"count":20,"interval":60}}}}' >/dev/null
sleep 2
rl=$(docker exec lab-client-c sh -c "for i in \$(seq 40); do dig +time=1 +tries=1 @$PI allowed.lab.example | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; done | sort | uniq -c | tr -s ' ' | tr '\n' ' '")
login; api PATCH /config '{"config":{"dns":{"rateLimit":{"count":1000,"interval":60}}}}' >/dev/null
grep -q REFUSED <<<"$rl"; expect_true M08 "Rate limiting" $? "$rl"

# ---- teleporter export ----
login
docker exec "$ADMIN" sh -c "curl -s -m 60 -H 'X-FTL-SID: $SID' -o /tmp/tp-$LABEL.zip http://$PI/api/teleporter"
docker cp "$ADMIN:/tmp/tp-$LABEL.zip" "$HERE/../results/$LABEL-teleporter.zip" >/dev/null
names=$(python3 -c 'import sys,zipfile; print(" ".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$HERE/../results/$LABEL-teleporter.zip" 2>&1)
grep -q 'pihole.toml' <<<"$names" && grep -q 'gravity.db' <<<"$names"
expect_true M10 "Teleporter export" $? "$(wc -w <<<"$names") files incl. pihole.toml, gravity.db"

# ---- persistence across restart ----
docker restart "$CT" >/dev/null
st=$(wait_healthy "$CT" 150); login
pl=$(api GET /lists | jq '.lists | length'); pd=$(api GET /domains | jq '.domains | length')
pg=$(api GET /groups | jq -r '[.groups[].name] | join(",")')
p1=$(dq client-a plain-list.lab.example); p2=$(dq client-a denyme.lab.example); p3=$(dq client-b ads.lab.example)
expect_eq M09 "Persistence across restart" "$st lists=$pl domains=$pd groups=$pg $p1 $p2 $p3" \
  "healthy lists=4 domains=3 groups=Default,unfiltered 0.0.0.0 0.0.0.0 10.10.0.66"

# ---- runtime posture ----
ftlpid=$(docker exec "$CT" pidof pihole-FTL)
posture P01 "pihole-FTL user" "$(docker exec "$CT" sh -c "ps -o user= -p $ftlpid | tr -d ' '; id -u pihole" | tr '\n' ':' | sed 's/:$//')" "pihole:1999"
posture P02 "pihole-FTL effective caps" "$(docker exec "$CT" sh -c "grep CapEff /proc/$ftlpid/status | awk '{print \$2}'")" 0000000000000000
posture P03 "NoNewPrivs (PID 1)" "$(docker exec "$CT" sh -c "awk '/NoNewPrivs/{print \$2}' /proc/1/status")" 1
posture P04 "Bounding capability set" "$(docker exec "$CT" sh -c 'capsh --decode=$(awk "/CapBnd/{print \$2}" /proc/1/status) | cut -d= -f2')" \
  "cap_chown,cap_dac_override,cap_fowner,cap_kill,cap_setgid,cap_setuid,cap_setfcap"
posture P05 "setuid/setgid files" "$(docker exec "$CT" sh -c 'find / -xdev -type f -perm /6000 2>/dev/null | wc -l')" 0
posture P06 "Package manager present" "$(docker exec "$CT" sh -c 'command -v apk >/dev/null && echo yes || echo no')" no
posture P07 "Owner of /etc/pihole data" "$(docker exec "$CT" stat -c '%u:%g' /etc/pihole/pihole.toml)" 1999:1999

echo "== $LABEL: $(grep -c '"PASS"' "$RES") pass, $(grep -c '"FAIL"' "$RES") fail, $(grep -c '"INFO"' "$RES") info"
