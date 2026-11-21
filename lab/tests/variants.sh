#!/usr/bin/env bash
# Variant scenarios V01-V08 from LAB-PLAN.md. Needs the lab infrastructure up
# and results/control-teleporter.zip from the control core run.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC2034  # LABEL is read by lib.sh
LABEL=variants
RES="$HERE/../results/variants.jsonl"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
: >"$RES"
: "${CONTROL_IMAGE:?}" "${SUBJECT_IMAGE:?}"
NET=pihole-lab_lab
ENVS=(-e TZ=UTC -e FTLCONF_webserver_api_password=lab-password -e FTLCONF_dns_listeningMode=ALL
      -e FTLCONF_dns_upstreams=172.30.0.10 -e FTLCONF_database_DBinterval=5
      -e FTLCONF_ntp_sync_active=false -e FTLCONF_ntp_ipv6_active=false)
CAPS7=(--cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID
       --cap-add SETGID --cap-add SETFCAP --cap-add KILL)
NNP=(--security-opt no-new-privileges:true)
LIMITS=(--pids-limit 256 --memory 512m --tmpfs /tmp:size=64m -e PIHOLE_UID=1999 -e PIHOLE_GID=1999)
HARDEN=("${CAPS7[@]}" "${NNP[@]}" "${LIMITS[@]}") # = deploy/docker-compose.yml
# DHCP runs on the separate non-internal "dhcp" network (see compose.lab.yml)
DNET=pihole-lab_dhcp
DHCP_ENV=(-e FTLCONF_dhcp_active=true -e FTLCONF_dhcp_start=172.31.0.200 -e FTLCONF_dhcp_end=172.31.0.220
          -e FTLCONF_dhcp_router=172.31.0.1 -e FTLCONF_dhcp_netmask=255.255.255.0)

run_pi() { # name ip image volume [docker-run options...]
  local n=$1 ip=$2 img=$3 vol=$4; shift 4
  docker rm -f "$n" >/dev/null 2>&1
  docker run -d --name "$n" --network "$NET" --ip "$ip" --dns 172.30.0.10 \
    -v "$vol:/etc/pihole" "${ENVS[@]}" "$@" "$img" >/dev/null
}
stop_pi() { docker rm -f "$1" >/dev/null 2>&1; }
blocking_state() { # -> "plain denyme tracker1" answers from client-a
  echo "$(dq client-a plain-list.lab.example) $(dq client-a denyme.lab.example) $(dq client-a tracker1.lab.example)"
}
run_dhcp_pi() { # name image [docker-run options...]; Pi-hole at 172.31.0.55
  local n=$1 img=$2; shift 2
  docker rm -f "$n" >/dev/null 2>&1; docker volume rm -f "$n" >/dev/null 2>&1
  # No lab DNS on this network: answer gravity's github lookup locally so it doesn't wait 120 s
  docker run -d --name "$n" --network "$DNET" --ip 172.31.0.55 \
    --add-host github.com:127.0.0.1 --add-host raw.githubusercontent.com:127.0.0.1 \
    -v "$n:/etc/pihole" "${ENVS[@]}" "${DHCP_ENV[@]}" "$@" "$img" >/dev/null
}
stop_dhcp_pi() { docker rm -f "$1" >/dev/null 2>&1; docker volume rm -f "$1" >/dev/null 2>&1; }
dhcp_client() { # -> leased IP or "none"
  docker run --rm --network "$DNET" --ip 172.31.0.30 --cap-add NET_ADMIN --cap-add NET_RAW \
    pihole-lab-helper udhcpc -i eth0 -n -q -f -t 4 -T 2 -s /bin/true 2>&1 |
    sed -n 's/.*lease of \([0-9.]*\) obtained.*/\1/p' | head -1 | grep . || echo none
}
dhcp_result() { # container -> "state lease_in_range=… in_api=…"
  local st lease seen
  st=$(wait_healthy "$1" 150); lease=$(dhcp_client); PI=172.31.0.55; login
  seen=$(api GET /dhcp/leases | jq -r '[.leases[].ip]|join(",")' 2>/dev/null)
  echo "$st lease_in_range=$([[ $lease =~ ^172\.31\.0\.2[0-2][0-9]$ ]] && echo yes || echo "no($lease)") in_api=$([ -n "$seen" ] && [ "$seen" = "$lease" ] && echo yes || echo "no($seen)")"
}
echo "== variants"

# ---- V01 migration: control-configured volume -> subject ----
docker volume rm -f lab-migrate >/dev/null
PI=172.30.0.57
run_pi lab-migrate "$PI" "$CONTROL_IMAGE" lab-migrate
st=$(wait_healthy lab-migrate 150); echo "  control on lab-migrate: $st, $(setup_pihole)"
base=$(blocking_state); stop_pi lab-migrate
run_pi lab-migrate "$PI" "$SUBJECT_IMAGE" lab-migrate "${HARDEN[@]}"
st=$(wait_healthy lab-migrate 150); login
got="$st lists=$(api GET /lists | jq '.lists|length') domains=$(api GET /domains | jq '.domains|length') blocking=[$(blocking_state)] owner=$(docker exec lab-migrate stat -c %u:%g /etc/pihole/gravity.db)"
expect_eq V01 "Migration control -> subject" "$got" \
  "healthy lists=4 domains=3 blocking=[0.0.0.0 0.0.0.0 0.0.0.0] owner=1999:1999"
[ "$base" = "0.0.0.0 0.0.0.0 0.0.0.0" ] || echo "  note: control baseline blocking was [$base]"

# ---- V02 rollback: same volume -> control again ----
stop_pi lab-migrate
run_pi lab-migrate "$PI" "$CONTROL_IMAGE" lab-migrate
st=$(wait_healthy lab-migrate 150); login
got="$st lists=$(api GET /lists | jq '.lists|length') domains=$(api GET /domains | jq '.domains|length') blocking=[$(blocking_state)] owner=$(docker exec lab-migrate stat -c %u:%g /etc/pihole/gravity.db)"
expect_eq V02 "Rollback subject -> control" "$got" \
  "healthy lists=4 domains=3 blocking=[0.0.0.0 0.0.0.0 0.0.0.0] owner=1000:1000"
stop_pi lab-migrate; docker volume rm -f lab-migrate >/dev/null

# ---- V03 teleporter: control export -> fresh subject ----
docker volume rm -f lab-teleport >/dev/null
PI=172.30.0.58
run_pi lab-teleport "$PI" "$SUBJECT_IMAGE" lab-teleport "${HARDEN[@]}"
st=$(wait_healthy lab-teleport 150); login
docker cp "$HERE/../results/control-teleporter.zip" "$ADMIN:/tmp/import.zip" >/dev/null
imp=$(docker exec "$ADMIN" curl -s -m 120 -H "X-FTL-SID: $SID" -F "file=@/tmp/import.zip" "http://$PI/api/teleporter" | jq -c '.files | length' 2>&1)
sleep 5; st=$(wait_healthy lab-teleport 150); login
api POST /action/gravity >/dev/null; sleep 3
imported=$([ "$imp" -gt 0 ] 2>/dev/null && echo yes || echo "no($imp)")
got="imported=$imported lists=$(api GET /lists | jq '.lists|length') domains=$(api GET /domains | jq '.domains|length') groups=$(api GET /groups | jq -r '[.groups[].name]|join(",")') blocking=[$(blocking_state)] b-ads=$(dq client-b ads.lab.example) nas=$(dq client-a nas.home.lab)"
want="imported=yes lists=4 domains=3 groups=Default,unfiltered blocking=[0.0.0.0 0.0.0.0 0.0.0.0] b-ads=10.10.0.66 nas=10.10.0.50"
expect_eq V03 "Teleporter control -> subject" "$got" "$want"
stop_pi lab-teleport; docker volume rm -f lab-teleport >/dev/null

# ---- V04 DHCP on the subject, documented DHCP settings ----
# 7 caps + NET_ADMIN + NET_RAW, no-new-privileges removed (see deploy/docker-compose.yml)
run_dhcp_pi lab-dhcp "$SUBJECT_IMAGE" "${CAPS7[@]}" "${LIMITS[@]}" --cap-add NET_ADMIN --cap-add NET_RAW
expect_eq V04 "DHCP (subject, documented settings)" "$(dhcp_result lab-dhcp)" "healthy lease_in_range=yes in_api=yes"
stop_dhcp_pi lab-dhcp

# ---- V09 DHCP on the subject with no-new-privileges kept ----
# Expected to fail: FTL runs as pihole and cannot gain NET_ADMIN from its file
# capabilities under no-new-privileges, so dnsmasq refuses the DHCP config.
run_dhcp_pi lab-dhcp "$SUBJECT_IMAGE" "${HARDEN[@]}" --cap-add NET_ADMIN --cap-add NET_RAW
st=$(wait_healthy lab-dhcp 150)
msg=$(docker logs lab-dhcp 2>&1 | grep -c 'missing required capability NET_ADMIN')
if [ "$st" != healthy ] && [ "$msg" -gt 0 ]; then record V09 "DHCP + no-new-privileges fails" PASS "fails as documented: $st, dnsmasq reports missing NET_ADMIN"
else record V09 "DHCP + no-new-privileges fails" FAIL "state=$st missing-NET_ADMIN messages=$msg"; fi
stop_dhcp_pi lab-dhcp

# ---- V05 DHCP on control (Docker default caps + NET_ADMIN) ----
run_dhcp_pi lab-dhcp "$CONTROL_IMAGE" --cap-add NET_ADMIN
expect_eq V05 "DHCP (control + NET_ADMIN)" "$(dhcp_result lab-dhcp)" "healthy lease_in_range=yes in_api=yes"
stop_dhcp_pi lab-dhcp

# ---- V06 DHCP enabled without NET_ADMIN: parity with upstream ----
# start.sh intends to switch DHCP off, but FTLCONF_dhcp_active makes the
# setting read-only, so FTL stops on a config error on both images.
run_dhcp_pi lab-dhcp "$CONTROL_IMAGE"
cst=$(wait_healthy lab-dhcp 150); cmsg=$(docker logs lab-dhcp 2>&1 | grep -c 'missing required capability NET_ADMIN')
stop_dhcp_pi lab-dhcp
run_dhcp_pi lab-dhcp "$SUBJECT_IMAGE" "${HARDEN[@]}"
sst=$(wait_healthy lab-dhcp 150); smsg=$(docker logs lab-dhcp 2>&1 | grep -c 'missing required capability NET_ADMIN')
stop_dhcp_pi lab-dhcp
expect_eq V06 "DHCP without NET_ADMIN (parity)" "subject=$sst/crit=$([ "$smsg" -gt 0 ] && echo yes || echo no)" \
  "subject=$cst/crit=$([ "$cmsg" -gt 0 ] && echo yes || echo no)"

# ---- V07 / V08 host networking ----
hostnet() { # nnp(yes|no) -> "state answer bind_errors"
  local nnp=() a e s
  [ "$1" = yes ] && nnp=(--security-opt no-new-privileges:true)
  docker rm -f lab-hostnet >/dev/null 2>&1; docker volume rm -f lab-hostnet >/dev/null
  docker run -d --name lab-hostnet --network host -v lab-hostnet:/etc/pihole \
    --add-host github.com:127.0.0.1 --add-host raw.githubusercontent.com:127.0.0.1 \
    -e TZ=UTC -e FTLCONF_webserver_api_password=lab-password -e FTLCONF_dns_listeningMode=ALL \
    -e FTLCONF_ntp_sync_active=false -e FTLCONF_ntp_ipv6_active=false -e FTLCONF_ntp_ipv4_active=false \
    -e PIHOLE_UID=1999 -e PIHOLE_GID=1999 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID \
    --cap-add SETGID --cap-add SETFCAP --cap-add KILL --cap-add NET_BIND_SERVICE "${nnp[@]}" \
    "$SUBJECT_IMAGE" >/dev/null
  s=$(wait_healthy lab-hostnet 90)
  # keep only address lines; dig prints errors such as "connection refused" otherwise
  a=$(docker run --rm --network host pihole-lab-helper dig +short +time=2 +tries=1 @127.0.0.1 pi.hole 2>&1 | grep -E '^[0-9.]+$|^[0-9a-f:]+$' | head -1)
  # start.sh streams FTL.log to stdout, so this works even if the container exited
  e=$(docker logs lab-hostnet 2>&1 | grep -ciE "permission denied|cannot bind|failed to create listening socket")
  docker rm -f lab-hostnet >/dev/null 2>&1; docker volume rm -f lab-hostnet >/dev/null
  echo "$s answer=${a:-none} bind_errors=$e"
}
busy=$(docker run --rm --network host pihole-lab-helper sh -c 'netstat -lnu 2>/dev/null | grep -c ":53 "')
if [ "${busy:-0}" -gt 0 ]; then
  record V07 "Host net + no-new-privileges" SKIP "host port 53 in use"
  record V08 "Host net without no-new-privileges" SKIP "host port 53 in use"
else
  r=$(hostnet yes)
  if [[ $r == *answer=none* && $r != *bind_errors=0* ]]; then record V07 "Host net + no-new-privileges" PASS "fails as documented: $r"
  else record V07 "Host net + no-new-privileges" FAIL "expected FTL unable to bind :53, got: $r"; fi
  r=$(hostnet no)
  if [[ $r == healthy* && $r != *answer=none* ]]; then record V08 "Host net without no-new-privileges" PASS "$r"
  else record V08 "Host net without no-new-privileges" FAIL "$r"; fi
fi

echo "== variants: $(grep -c '"PASS"' "$RES") pass, $(grep -c '"FAIL"' "$RES") fail, $(grep -c '"SKIP"' "$RES") skip"
