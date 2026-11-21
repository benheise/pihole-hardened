#!/usr/bin/env bash
# Build the lab, run every scenario in LAB-PLAN.md and write
# lab/results/LAB-REPORT.md. Exits non-zero if the verdict is FAIL.
#
# usage: lab/run-lab.sh [--keep]      --keep leaves the containers running
# env:   CONTROL_IMAGE   default docker.io/pihole/pihole:<PIHOLE_DOCKER_TAG>
#        SUBJECT_IMAGE   default pihole-hardened:lab (built from this repo if missing)
#        LAB_BASE_IMAGE  base for the helper image (default: pinned Alpine via mirror.gcr.io)
#        LAB_BUILD_ARGS  extra "docker build" arguments, e.g. proxy settings
set -euo pipefail
LAB=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$LAB")
KEEP=no; [ "${1:-}" = --keep ] && KEEP=yes
# shellcheck source=/dev/null
source <(bash "$REPO/scripts/upstream-env.sh")
export CONTROL_IMAGE=${CONTROL_IMAGE:-docker.io/pihole/pihole:$PIHOLE_DOCKER_TAG}
export SUBJECT_IMAGE=${SUBJECT_IMAGE:-pihole-hardened:lab}
read -ra EXTRA <<<"${LAB_BUILD_ARGS:-}"
COMPOSE=(docker compose -f "$LAB/compose.lab.yml")
cd "$LAB"

cleanup() {
  [ "$KEEP" = yes ] && { echo "== --keep: lab left running"; return; }
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f lab-migrate lab-teleport lab-dhcp lab-hostnet >/dev/null 2>&1 || true
  docker volume rm -f lab-migrate lab-teleport lab-dhcp lab-hostnet >/dev/null 2>&1 || true
}
trap cleanup EXIT
start=$(date +%s)

echo "== images"
docker build -q "${EXTRA[@]}" ${LAB_BASE_IMAGE:+--build-arg BASE_IMAGE="$LAB_BASE_IMAGE"} \
  -t pihole-lab-helper "$LAB/images/helper" >/dev/null
# Registry references (the release workflow passes image@sha256:...) are pulled;
# a missing local name is built from this repo.
if ! docker image inspect "$SUBJECT_IMAGE" >/dev/null 2>&1; then
  case "$SUBJECT_IMAGE" in
    *@sha256:* | *.*/*) docker pull -q "$SUBJECT_IMAGE" >/dev/null ;;
  esac
fi
if ! docker image inspect "$SUBJECT_IMAGE" >/dev/null 2>&1; then
  echo "   building $SUBJECT_IMAGE from this repo"
  [ -d "$REPO/upstream" ] || git clone -q --depth 1 --branch "$PIHOLE_DOCKER_TAG" \
    https://github.com/pi-hole/docker-pi-hole.git "$REPO/upstream"
  docker build -q "${EXTRA[@]}" --build-arg FTL_VERSION="$FTL_VERSION" --build-arg CORE_VERSION="$CORE_VERSION" \
    --build-arg WEB_VERSION="$WEB_VERSION" --build-arg PIHOLE_DOCKER_TAG="$PIHOLE_DOCKER_TAG" \
    -t "$SUBJECT_IMAGE" "$REPO" >/dev/null
fi
docker image inspect "$CONTROL_IMAGE" >/dev/null 2>&1 || docker pull -q "$CONTROL_IMAGE" >/dev/null
echo "   control: $CONTROL_IMAGE"
echo "   subject: $SUBJECT_IMAGE"

rm -rf "$LAB/results"; mkdir -p "$LAB/results"
jq -n --arg date "$(date -u +%FT%TZ)" --arg docker "Docker $(docker version -f '{{.Server.Version}}')" \
  --arg arch "$(docker version -f '{{.Server.Arch}}')" \
  --arg ci "$CONTROL_IMAGE" --arg cid "$(docker image inspect -f '{{.Id}}' "$CONTROL_IMAGE")" \
  --arg si "$SUBJECT_IMAGE" --arg sid "$(docker image inspect -f '{{.Id}}' "$SUBJECT_IMAGE")" \
  '{date:$date, docker:$docker, arch:$arch, control_image:$ci, control_id:$cid, subject_image:$si, subject_id:$sid}' \
  >"$LAB/results/meta.json"

echo "== starting lab topology"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d >/dev/null

bash "$LAB/tests/core.sh" control 172.30.0.53 lab-pihole-control || true
bash "$LAB/tests/core.sh" subject 172.30.0.54 lab-pihole-subject || true
"${COMPOSE[@]}" stop pihole-control pihole-subject >/dev/null
bash "$LAB/tests/variants.sh" || true

echo "== report (lab ran for $(( ($(date +%s) - start) / 60 )) min)"
python3 "$LAB/report.py" "$LAB/results"
