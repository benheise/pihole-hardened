#!/usr/bin/env bash
# Scan one platform of an image and write its release evidence. Does not gate:
# the release workflow gates in a separate step, so the reports survive a
# failed gate for triage.
#
# usage: scripts/scan-image.sh <image-ref> <platform> <out-dir>
# writes, with KEY = platform with "/" replaced by "-" (e.g. linux-arm-v7):
#   trivy-KEY.json        full Trivy result (VEX and .trivyignore applied)
#   trivy-KEY.sarif       same, for GitHub code scanning
#   trivy-KEY.txt         same, human-readable table
#   vuln-KEY.cosign.json  cosign vulnerability-attestation predicate
#   sbom-KEY.spdx.json    SPDX 2.3 SBOM (Alpine packages + Pi-hole components)
#   sbom-KEY.cdx.json     CycloneDX 1.6 SBOM (same content)
# needs: trivy, docker, python3
set -euo pipefail
REF=${1:?usage: scan-image.sh <image-ref> <platform> <out-dir>}
PLAT=${2:?platform, e.g. linux/arm64}
OUT=${3:?output directory}
cd "$(dirname "$0")/.."
KEY=$(tr / - <<<"$PLAT")
mkdir -p "$OUT"

trivy image --quiet --platform "$PLAT" --scanners vuln \
  --vex vex/pihole.openvex.json --ignorefile .trivyignore \
  --format json --output "$OUT/trivy-$KEY.json" "$REF"
trivy convert --quiet --format sarif --output "$OUT/trivy-$KEY.sarif" "$OUT/trivy-$KEY.json"
trivy convert --quiet --format table --output "$OUT/trivy-$KEY.txt" "$OUT/trivy-$KEY.json"
trivy convert --quiet --format cosign-vuln --output "$OUT/vuln-$KEY.cosign.json" "$OUT/trivy-$KEY.json"
trivy image --quiet --platform "$PLAT" --format spdx-json --output "$OUT/sbom-$KEY.spdx.json" "$REF"
trivy image --quiet --platform "$PLAT" --format cyclonedx --output "$OUT/sbom-$KEY.cdx.json" "$REF"

# Trivy can't see pihole-FTL (static binary) or the Pi-hole scripts; add them
# from the build-input record the Dockerfile writes into the image.
cid=$(docker create --platform "$PLAT" "$REF")
tmp=$(mktemp -d)
docker cp -q "$cid:/usr/share/pihole-hardened/build-inputs.txt" "$OUT/build-inputs-$KEY.txt"
docker cp -q "$cid:/pihole.docker.tag" "$tmp/docker.tag"
docker rm "$cid" >/dev/null
python3 -I scripts/sbom-add-pihole.py "$OUT/build-inputs-$KEY.txt" "$(tr -d '[:space:]' <"$tmp/docker.tag")" \
  "$OUT/sbom-$KEY.spdx.json" "$OUT/sbom-$KEY.cdx.json"
rm -rf "$tmp"

jq -r --arg k "$KEY" '[.Results[]?.Vulnerabilities[]?] as $v
  | "\($k): \($v | length) findings (" +
    (["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"] | map(. as $s | "\($s)=\([$v[] | select(.Severity == $s)] | length)") | join(" ")) + ")"' \
  "$OUT/trivy-$KEY.json"
