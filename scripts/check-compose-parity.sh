#!/usr/bin/env bash
# The two compose files must differ only in where the image comes from:
# deploy/docker-compose.yml (digest set by update.sh) and
# deploy/docker-compose.dockerhub.yml (Docker Hub tag by default). The smoke
# test exercises the first one's settings; this keeps the second from drifting
# away from what was tested. Compares the rendered configuration, so comments
# and formatting may differ. needs: docker compose, jq
set -euo pipefail
cd "$(dirname "$0")/../deploy"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
render() { # <file> -> normalized JSON without the image
  PIHOLE_IMAGE=example.invalid/image:tag docker compose --project-name parity --project-directory "$d" \
    -f "$1" config --format json | jq -S 'del(.services.pihole.image)'
}
if diff <(render docker-compose.yml) <(render docker-compose.dockerhub.yml); then
  echo "ok  compose files are identical apart from the image"
else
  echo "::error::deploy/docker-compose.dockerhub.yml differs from deploy/docker-compose.yml in more than the image (diff above: '<' is docker-compose.yml)" >&2
  exit 1
fi
# and the Docker Hub file must work with no .env at all
img=$(docker compose --project-name parity --project-directory "$d" -f docker-compose.dockerhub.yml config --format json | jq -r .services.pihole.image)
[[ "$img" == docker.io/*/pihole-hardened:latest ]] || { echo "::error::unexpected default image: $img" >&2; exit 1; }
echo "ok  default image without .env: $img"
