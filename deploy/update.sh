#!/usr/bin/env bash
# Verify the latest release and move the running Pi-hole to it. Rolls back to
# the previous digest if the new container doesn't become healthy.
# Run by deploy/pihole-update.timer. Needs docker compose, cosign 3.x, curl,
# jq, and verify-release.sh next to this script.
#
# env: REPO=owner/repo (required; read from PIHOLE_REPO in .env when unset,
#      which deploy/install.sh writes), PIHOLE_DIR (default /opt/pihole)
#      IMAGE_REPO=docker.io/owner/pihole-hardened to pull the Docker Hub copy
#      instead of GHCR (same digest and signatures; verify-release.sh checks
#      that the signed release names that copy).
#      ALLOW_DOWNGRADE=1 to move to an older release on purpose. Without it,
#      a "latest" that is older than what runs is refused: every release is
#      signed, so a re-published old release would otherwise verify fine.
set -euo pipefail
DIR=${PIHOLE_DIR:-/opt/pihole}
cd "$DIR"
# Registry login made by install.sh for a private package (root-only folder)
if [ -d "$DIR/.docker" ]; then export DOCKER_CONFIG="$DIR/.docker"; fi
REPO=${REPO:-$(sed -n 's/^PIHOLE_REPO=//p' .env 2>/dev/null || true)}
if [ -z "$REPO" ]; then
  echo "REPO is not set. Run: sudo REPO=owner/repo $0   (or run deploy/install.sh once)" >&2
  exit 1
fi

out=$("$DIR/verify-release.sh" "$REPO" latest)
new=$(tail -1 <<<"$out")
new_ver=$(sed -n 's/^version //p' <<<"$out")
cur=$(sed -n 's/^PIHOLE_IMAGE=//p' .env 2>/dev/null || true)
cur_ver=$(sed -n 's/^PIHOLE_VERSION=//p' .env 2>/dev/null || true)
if [ "$new" = "$cur" ]; then echo "up to date: $cur_ver $cur"; exit 0; fi

# Versions look like 2026.10.1-h42: upstream tag, then this pipeline's run number
if [ -n "$cur_ver" ] && [ "${ALLOW_DOWNGRADE:-0}" != 1 ] &&
   [ "$(printf '%s\n%s\n' "$cur_ver" "$new_ver" | sort -V | tail -1)" != "$new_ver" ]; then
  echo "refusing to downgrade from $cur_ver to $new_ver (set ALLOW_DOWNGRADE=1 to override)" >&2
  exit 1
fi
echo "updating: ${cur_ver:-<none>} -> $new_ver ($new)"

set_kv() { # KEY value
  if grep -q "^$1=" .env 2>/dev/null; then sed -i "s|^$1=.*|$1=$2|" .env
  else echo "$1=$2" >>.env; fi
}
set_image() { set_kv PIHOLE_IMAGE "$1"; set_kv PIHOLE_VERSION "$2"; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' pihole 2>/dev/null || echo missing; }

# Pull before touching the running container, so a pull failure changes nothing
docker pull -q "$new" >/dev/null
set_image "$new" "$new_ver"
docker compose up -d pihole

status=starting
for _ in $(seq 60); do
  status=$(health)
  case "$status" in
    healthy) echo "healthy on $new_ver"; docker image prune -f >/dev/null; exit 0 ;;
    unhealthy | missing) break ;;
  esac
  sleep 5
done

echo "new image is $status; rolling back to ${cur_ver:-<none>}" >&2
if [ -n "$cur" ]; then
  set_image "$cur" "$cur_ver"
  docker compose up -d pihole
fi
exit 1
