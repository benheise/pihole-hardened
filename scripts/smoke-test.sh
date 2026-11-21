#!/usr/bin/env bash
# Run the image under the production hardening settings and exercise every
# runtime path: startup, DNS, API login, upstream's API guard on the settings
# that would let an admin run code, gravity and log rotation (the cron
# jobs), the update checker, and a clean shutdown. Also checks the posture the
# image and compose file promise: no setuid files or apk, no NTP listener,
# repository metadata not served, versions reported, and root not writing
# through paths the unprivileged pihole user controls.
#
# usage: scripts/smoke-test.sh <image>
set -euo pipefail
IMG="${1:?usage: smoke-test.sh <image>}"
N="pihole-smoke-$$"
SECRET=$(mktemp -d)
cleanup() { docker rm -f "$N" >/dev/null 2>&1 || true; rm -rf "$SECRET"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; docker logs "$N" 2>&1 | tail -40; exit 1; }
printf 'smoke-test\n' >"$SECRET/webpassword"

# Same capability set and options as deploy/docker-compose.yml. The password
# arrives the compose way, as a secret file, not as an environment variable.
docker run -d --name "$N" -v /etc/pihole \
  -v "$SECRET/webpassword:/run/secrets/webpassword:ro" -e WEBPASSWORD_FILE=webpassword \
  -e TZ=UTC -e FTLCONF_dns_listeningMode=ALL \
  -e FTLCONF_ntp_ipv4_active=false -e FTLCONF_ntp_ipv6_active=false -e FTLCONF_ntp_sync_active=false \
  -e 'FTLCONF_webserver_advancedOpts=hide_files_patterns=**/.*' \
  -e FTLCONF_webserver_session_restore=false \
  -e PIHOLE_UID=1999 -e PIHOLE_GID=1999 \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --cap-add SETUID --cap-add SETGID --cap-add SETFCAP \
  --cap-add KILL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 512m --tmpfs /tmp:size=64m \
  "$IMG" >/dev/null

status=starting
for _ in $(seq 60); do
  status=$(docker inspect -f '{{if .State.Running}}{{.State.Health.Status}}{{else}}exited{{end}}' "$N")
  case "$status" in healthy|exited) break ;; esac
  sleep 2
done
[ "$status" = healthy ] || fail "container is $status, not healthy"
echo "ok   healthy"

[ "$(docker exec "$N" dig +short @127.0.0.1 pi.hole)" = 127.0.0.1 ] || fail "pi.hole did not resolve"
echo "ok   DNS answers"

[ "$(docker exec "$N" ps -o user= -p "$(docker exec "$N" pidof pihole-FTL)" | tr -d ' ')" = pihole ] \
  || fail "pihole-FTL is not running as the pihole user"
[ "$(docker exec "$N" sh -c 'grep CapEff /proc/$(pidof pihole-FTL)/status | cut -f2')" = 0000000000000000 ] \
  || fail "pihole-FTL has effective capabilities"
echo "ok   FTL runs as pihole with no capabilities"

sid=$(docker exec "$N" curl -sk -X POST https://127.0.0.1/api/auth -d '{"password":"smoke-test"}' | jq -r '.session | select(.valid) | .sid')
[ -n "$sid" ] || fail "API login with the secret-file password failed"
docker inspect -f '{{json .Config.Env}}' "$N" | grep -q 'smoke-test' && fail "password visible in the container environment"
echo "ok   API login (password from secret file, not in the environment)"

# The admin-to-code-execution guard is upstream's: the API refuses to change
# the settings that would let a logged-in admin (or a stolen session) run
# code inside the container: the web root (server-side Lua pages) and raw
# dnsmasq lines (script hooks). If a Pi-hole update ever loosens that, the
# hardening in this image no longer contains a web-interface compromise.
for change in '{"config":{"webserver":{"paths":{"webroot":"/etc/pihole"}}}}' \
              '{"config":{"misc":{"dnsmasq_lines":["dhcp-script=/bin/true"]}}}'; do
  code=$(docker exec "$N" curl -sk -o /dev/null -w '%{http_code}' -X PATCH https://127.0.0.1/api/config \
    -H "sid: $sid" -d "$change")
  [ "$code" = 400 ] || fail "the API accepted $change (HTTP $code)"
done
[ "$(docker exec "$N" pihole-FTL --config webserver.paths.webroot)" = /var/www/html ] || fail "web root changed through the API"
[ "$(docker exec "$N" pihole-FTL --config misc.dnsmasq_lines)" = "[]" ] || fail "dnsmasq lines changed through the API"
code=$(docker exec "$N" curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/api/config/dns/port)
[ "$code" = 401 ] || fail "the API answered a config read without a session (HTTP $code)"
echo "ok   API refuses web-root and dnsmasq-line changes; config needs a session"

# Pre-login attack surface: only what the login page needs is served
for p in /admin/.gitignore /admin/.github/dependabot.yml /admin/README.md /admin/package-lock.json; do
  code=$(docker exec "$N" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1$p")
  [ "$code" = 404 ] || fail "$p is served before login (HTTP $code)"
done
[ "$(docker exec "$N" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/admin/login)" = 200 ] || fail "login page not served"
echo "ok   repository metadata not served; login page is"

docker exec "$N" sh -c 'cat /proc/net/udp /proc/net/udp6 2>/dev/null | grep -q ":007B "' && fail "NTP server is listening on 123/udp"
echo "ok   no NTP listener"

docker exec "$N" sh -c 'PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole updateGravity >/dev/null 2>&1' \
  || fail "gravity update (weekly cron job) failed"
echo "ok   gravity update"

# Rotation failures are silent (exit 0), so check for errors and rotated files
out=$(docker exec "$N" pihole flush once quiet 2>&1 || true)
if grep -q 'Permission denied' <<<"$out"; then fail "log rotation denied: $out"; fi
[ "$(docker exec "$N" sh -c 'ls /var/log/pihole/*.1 2>/dev/null | wc -l')" -gt 0 ] || fail "logs were not rotated"
echo "ok   log rotation"

docker exec "$N" sh -c 'PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole updatechecker >/dev/null 2>&1' \
  || fail "update checker failed"
versions=$(docker exec "$N" cat /etc/pihole/versions)
for k in CORE_VERSION WEB_VERSION FTL_VERSION DOCKER_VERSION; do
  v=$(sed -n "s/^$k=//p" <<<"$versions")
  case "$v" in ""|null) fail "$k is '$v' in /etc/pihole/versions" ;; esac
done
echo "ok   update checker; versions reported ($(sed -n 's/^CORE_VERSION=//p' <<<"$versions"), $(sed -n 's/^WEB_VERSION=//p' <<<"$versions"), $(sed -n 's/^FTL_VERSION=//p' <<<"$versions"))"

# Root must not write through paths the unprivileged pihole user controls
# (scripts/patch-upstream.sh). Plant what a compromised FTL could plant, then
# run every job in root's crontab the way crond does, and restart.
docker exec "$N" sh -c 'echo canary > /canary && chmod 600 /canary'
docker exec -u pihole "$N" sh -c '
  rm -f /var/log/pihole/pihole_updateGravity.log /etc/pihole/adlists.list
  ln -s /canary /var/log/pihole/pihole_updateGravity.log
  ln -s /created-by-root /etc/pihole/adlists.list' || fail "could not plant the test symlinks as the pihole user"
docker exec "$N" sh -c 'crontab -l | grep -v "^#" | grep . | sed -E "s/^([^ ]+ +){5}//" | while IFS= read -r job; do sh -c "$job" >/dev/null 2>&1 || true; done'
[ "$(docker exec "$N" cat /canary)" = canary ] || fail "a root cron job wrote through a symlink owned by the pihole user"
docker exec -u pihole "$N" rm -f /var/log/pihole/pihole_updateGravity.log
docker exec "$N" sh -c 'crontab -l | grep updateGravity | sed -E "s/^([^ ]+ +){5}//" | sh >/dev/null 2>&1'
[ "$(docker exec "$N" stat -c %U /var/log/pihole/pihole_updateGravity.log)" = pihole ] \
  && docker exec "$N" test -s /var/log/pihole/pihole_updateGravity.log || fail "the gravity cron job no longer writes its log"
docker restart "$N" >/dev/null
for _ in $(seq 60); do
  [ "$(docker inspect -f '{{if .State.Running}}{{.State.Health.Status}}{{else}}exited{{end}}' "$N")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$N")" = healthy ] || fail "not healthy after a restart with a planted adlists.list symlink"
docker exec "$N" test -e /created-by-root && fail "root created a file through a dangling symlink in /etc/pihole at start"
docker exec -u pihole "$N" rm -f /etc/pihole/adlists.list
echo "ok   root does not write through pihole-owned paths (cron jobs, startup); gravity job still logs"

docker exec "$N" sh -c '[ -z "$(find / -xdev -type f -perm /6000 2>/dev/null)" ] && ! command -v apk >/dev/null' \
  || fail "setuid files or the apk binary are present"
echo "ok   no setuid files, no apk"

start=$(date +%s)
docker stop -t 30 "$N" >/dev/null
took=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$N")
[ "$code" = 0 ] && [ "$took" -lt 20 ] || fail "unclean shutdown: exit $code after ${took}s"
echo "ok   clean shutdown in ${took}s"
echo "PASS"
