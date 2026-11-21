#!/usr/bin/env bash
# Verify a pihole-hardened release before deploying it. Checks, in order:
#   1. SHA256SUMS was signed by this repository's release workflow (keyless)
#   2. image-digests.json matches SHA256SUMS
#   3. the image index was signed by the build workflow
#   4. every platform image carries signed SPDX, CycloneDX, vulnerability and
#      VEX attestations from the release workflow
#   5. SLSA build provenance (only if gh is installed and logged in)
#
# usage: scripts/verify-release.sh <owner/repo> [version|latest]
# env:   IMAGE_REPO  verify and print a registry copy instead of GHCR, e.g.
#                    docker.io/owner/pihole-hardened. It must be listed in the
#                    release's signed image-digests.json; the digest is the
#                    same in every registry and the signatures travel with it.
# needs: cosign 3.x (the release signs with cosign 3's bundle format), curl,
#        jq, sha256sum; optional: gh
# Progress goes to stderr. stdout gets two lines: "version <release>" and,
# last, the verified image@digest, so scripts can deploy exactly what was
# checked and refuse to move backwards (deploy/update.sh does both).
set -euo pipefail
REPO=${1:?usage: verify-release.sh <owner/repo> [version|latest]}
V=${2:-latest}
ISS=https://token.actions.githubusercontent.com
W="https://github.com/$REPO/.github/workflows"
IMG="ghcr.io/${REPO,,}"
if [ "$V" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
else base="https://github.com/$REPO/releases/download/$V"; fi
log() { echo "$*" >&2; }
fail() { log "FAILED: $*"; exit 1; }

d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cd "$d"
for f in SHA256SUMS SHA256SUMS.sigstore.json image-digests.json; do
  curl -fsSLO "$base/$f" || fail "could not download $f from $base"
done

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$W/release.yml@refs/heads/main" --certificate-oidc-issuer "$ISS" \
  SHA256SUMS >/dev/null 2>&1 || fail "SHA256SUMS signature"
log "ok  SHA256SUMS signed by $REPO release workflow"

grep ' image-digests.json$' SHA256SUMS | sha256sum -c - >/dev/null 2>&1 || fail "image-digests.json checksum"
[ "$(jq -r .image image-digests.json)" = "$IMG" ] || fail "release names a different image"
if [ -n "${IMAGE_REPO:-}" ] && [ "$IMAGE_REPO" != "$IMG" ]; then
  jq -e --arg m "$IMAGE_REPO" '(.mirrors // []) | index($m) != null' image-digests.json >/dev/null \
    || fail "$IMAGE_REPO is not a registry copy named by this release (signed list: $(jq -c '.mirrors // []' image-digests.json))"
  IMG=$IMAGE_REPO
fi
DIGEST=$(jq -r .index_digest image-digests.json)
REL=$(jq -r .version image-digests.json)
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ && "$REL" =~ ^[A-Za-z0-9._-]+$ ]] || fail "image-digests.json has unexpected values"
if [ "$V" != latest ] && [ "$REL" != "$V" ]; then fail "asked for $V but the signed manifest describes $REL"; fi
log "ok  release $REL -> $IMG@$DIGEST"

cosign verify "$IMG@$DIGEST" \
  --certificate-identity "$W/build.yml@refs/heads/main" --certificate-oidc-issuer "$ISS" \
  >/dev/null 2>&1 || fail "image signature"
log "ok  image index signed by $REPO build workflow"

while read -r plat pdig; do
  for t in spdxjson cyclonedx vuln openvex; do
    cosign verify-attestation --type "$t" "$IMG@$pdig" \
      --certificate-identity "$W/release.yml@refs/heads/main" --certificate-oidc-issuer "$ISS" \
      >/dev/null 2>&1 || fail "$t attestation on $plat"
  done
  log "ok  $plat: SBOM (SPDX, CycloneDX), vulnerability and VEX attestations"
done < <(jq -r '.platforms[] | "\(.platform) \(.digest)"' image-digests.json)

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh attestation verify "oci://$IMG@$DIGEST" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/build.yml" >/dev/null 2>&1 || fail "SLSA provenance"
  log "ok  SLSA build provenance from $REPO build workflow"
else
  log "--  SLSA provenance not checked (needs gh, logged in)"
fi

echo "version $REL"
echo "$IMG@$DIGEST"
