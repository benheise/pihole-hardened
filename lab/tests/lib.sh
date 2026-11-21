#!/usr/bin/env bash
# Shared helpers for the lab suites. Source this; set PI (target IP),
# LABEL (control|subject|variants) and RES (results .jsonl file) first.
LAB_PASSWORD="lab-password"
ADMIN="lab-admin"
LISTS_BASE="http://lists.lab.example"
SID=""

# ---------- results ----------
record() { # id name status detail
  jq -nc --arg t "$LABEL" --arg id "$1" --arg n "$2" --arg s "$3" --arg d "$4" \
    '{target:$t,id:$id,name:$n,status:$s,detail:$d}' >>"$RES"
  printf '  %-4s %-5s %-34s %s\n' "$1" "$3" "$2" "$4"
}
expect_eq() { # id name actual expected
  if [ "$3" = "$4" ]; then record "$1" "$2" PASS "$3"
  else record "$1" "$2" FAIL "got '$3', want '$4'"; fi
}
expect_contains() { # id name actual needle
  if grep -qF -- "$4" <<<"$3"; then record "$1" "$2" PASS "$(tr '\n' ' ' <<<"$3" | cut -c1-90)"
  else record "$1" "$2" FAIL "got '$(tr '\n' ' ' <<<"$3" | cut -c1-90)', want '$4'"; fi
}
expect_true() { # id name condition-exit-code detail
  if [ "$3" -eq 0 ]; then record "$1" "$2" PASS "$4"; else record "$1" "$2" FAIL "$4"; fi
}
# Posture checks are pass/fail for the subject and informational for control
posture() { # id name actual expected
  if [ "$LABEL" != subject ]; then record "$1" "$2" INFO "$3"; return; fi
  expect_eq "$@"
}

# ---------- DNS from a client container ----------
dq() { # client name [type] -> answers, one per line
  local c=$1; shift
  docker exec "lab-$c" dig +time=2 +tries=1 +short @"$PI" "$@" 2>&1 | head -5
}
dstatus() { # client name [type] -> rcode
  local c=$1; shift
  docker exec "lab-$c" dig +time=2 +tries=1 @"$PI" "$@" 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}
dttl() { # client name -> TTL of the first answer
  local c=$1; shift
  docker exec "lab-$c" dig +time=2 +tries=1 +noall +answer @"$PI" "$@" 2>&1 | awk 'NR==1{print $2}'
}

# ---------- API via the admin container ----------
api() { # method path [json]
  if [ -n "${3:-}" ]; then
    printf '%s' "$3" | docker exec -i "$ADMIN" curl -s -m 300 -X "$1" \
      -H "X-FTL-SID: $SID" -H 'Content-Type: application/json' --data-binary @- "http://$PI/api$2"
  else
    docker exec "$ADMIN" curl -s -m 300 -X "$1" -H "X-FTL-SID: $SID" "http://$PI/api$2"
  fi
}
api_code() { # method path [json] -> HTTP status code
  docker exec -i "$ADMIN" curl -s -m 60 -o /dev/null -w '%{http_code}' -X "$1" \
    -H "X-FTL-SID: $SID" -H 'Content-Type: application/json' --data-binary "${3:-}" "http://$PI/api$2"
}
login() {
  SID=$(api POST /auth "{\"password\":\"$LAB_PASSWORD\"}" | jq -r '.session.sid // empty')
  [ -n "$SID" ]
}

# ---------- containers ----------
wait_healthy() { # container [timeout-seconds] -> prints final state
  local s="" i
  for ((i = 0; i < ${2:-120}; i += 2)); do
    s=$(docker inspect -f '{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}exited({{.State.ExitCode}}){{end}}' "$1" 2>/dev/null || echo missing)
    case "$s" in healthy | unhealthy | exited* | missing) break ;; esac
    sleep 2
  done
  echo "$s"
}

# ---------- standard Pi-hole configuration used by every scenario ----------
# Replaces the default internet blocklist with the lab lists, adds the
# domain entries, the "unfiltered" group for client-b, local DNS records,
# then runs gravity. Prints a one-line summary; returns non-zero on failure.
setup_pihole() {
  local addr gid out
  login || { echo "login failed"; return 1; }
  for addr in $(api GET /lists | jq -r '.lists[].address | @uri'); do
    api DELETE "/lists/$addr?type=block" >/dev/null
  done
  for f in block-domains block-hosts block-abp; do
    api POST "/lists?type=block" "{\"address\":\"$LISTS_BASE/$f.txt\",\"comment\":\"lab\"}" >/dev/null
  done
  api POST "/lists?type=allow" "{\"address\":\"$LISTS_BASE/allow-antigravity.txt\",\"comment\":\"lab\"}" >/dev/null
  api POST /domains/deny/exact '{"domain":"denyme.lab.example"}' >/dev/null
  api POST /domains/deny/regex "$(jq -nc --arg d '^tracker[0-9]+\.lab\.example$' '{domain:$d}')" >/dev/null
  api POST /domains/allow/exact '{"domain":"allowme.lab.example"}' >/dev/null
  gid=$(api POST /groups '{"name":"unfiltered","comment":"lab: no blocklists"}' | jq -r '.groups[0].id')
  api POST /clients "{\"client\":\"172.30.0.22\",\"groups\":[$gid]}" >/dev/null
  api PATCH /config '{"config":{"dns":{"hosts":["10.10.0.50 nas.home.lab"],"cnameRecords":["alias.home.lab,nas.home.lab"]}}}' >/dev/null
  sleep 3
  login || { echo "login failed after config change"; return 1; }
  out=$(api POST /action/gravity)
  sleep 3
  echo "lists=$(api GET /lists | jq '.lists | length') domains=$(api GET /domains | jq '.domains | length') unfiltered_gid=$gid gravity_done=$(grep -c 'Done' <<<"$out")"
}
