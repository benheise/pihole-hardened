#!/usr/bin/env bash
# Copy a signed image index to a second registry (Docker Hub) without changing
# it, together with everything attached to it or to its platform images:
# cosign signatures, SBOM/vulnerability/VEX attestations and SLSA provenance.
# Then point one or more tags at it and check each tag resolves to the digest
# that was signed.
#
# "oras cp -r" is used because the attachments are OCI referrers (cosign 3's
# default). Tested alternatives: "docker buildx imagetools create" copies the
# image but none of the attachments, and "cosign copy" 3.1.4 fails on them.
# The index digest is identical in both registries, so one signature covers
# both and a verifier can use either.
#
# usage: scripts/mirror-image.sh <source-image> <digest> <dest-image> <tag> [tag...]
#   e.g. mirror-image.sh ghcr.io/o/pihole-hardened sha256:... docker.io/o/pihole-hardened 2026.10.1-h7 latest
# needs: oras, logged in to both registries (docker login is enough)
# env:   MIRROR_PLAIN_HTTP=1 for local test registries without TLS
set -euo pipefail
SRC=${1:?source image}; DIGEST=${2:?digest}; DST=${3:?destination image}; shift 3
[ $# -gt 0 ] || { echo "at least one tag is required" >&2; exit 1; }
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "not a digest: $DIGEST" >&2; exit 1; }
for t in "$@"; do
  [[ "$t" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] || { echo "not a valid tag: $t" >&2; exit 1; }
done
cp_flags=(); flag=()
if [ "${MIRROR_PLAIN_HTTP:-0}" = 1 ]; then cp_flags=(--from-plain-http --to-plain-http); flag=(--plain-http); fi

first=$1; shift
oras cp -r "${cp_flags[@]}" "$SRC@$DIGEST" "$DST:$first"
[ $# -eq 0 ] || oras tag "${flag[@]}" "$DST:$first" "$@"

for t in "$first" "$@"; do
  got=$(oras resolve "${flag[@]}" "$DST:$t")
  [ "$got" = "$DIGEST" ] || { echo "::error::$DST:$t is $got, not the signed $DIGEST" >&2; exit 1; }
  echo "ok  $DST:$t -> $DIGEST"
done
