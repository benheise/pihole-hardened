#!/usr/bin/env bash
# Assemble the compliance bundle attached to every release.
#
# usage: scripts/build-compliance-bundle.sh <artifacts-dir> <out-dir>
#   <artifacts-dir>/scan/   scan-image.sh output for every platform, plus
#                           grype-KEY.json and platform-KEY.txt
#   <artifacts-dir>/lab/lab-<arch>/LAB-REPORT.md   lab results per runner arch
# env: IMAGE DIGEST VERSION DOCKER_TAG REPO (set by release.yml)
#      MIRROR_IMAGES  optional, space-separated registry copies of the same
#                     index (e.g. docker.io/owner/pihole-hardened)
#      SKIP_PROVENANCE=1 skips "gh attestation download" (local testing)
set -euo pipefail
A=${1:?artifacts dir}; O=${2:?output dir}
: "${IMAGE:?}" "${DIGEST:?}" "${VERSION:?}" "${DOCKER_TAG:?}" "${REPO:?}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=/dev/null
source <(bash "$ROOT/scripts/upstream-env.sh")
S="$A/scan"
mkdir -p "$O"
now=$(date -u +%FT%TZ)
run_url="${GITHUB_SERVER_URL:-https://github.com}/$REPO/actions/runs/${GITHUB_RUN_ID:-local}"

# ---- evidence files, renamed for readers ----
cp "$S"/sbom-*.spdx.json "$S"/sbom-*.cdx.json "$S"/build-inputs-*.txt "$O"/
for f in "$S"/trivy-*.json; do cp "$f" "$O/vulnerabilities-$(basename "$f")"; done
for f in "$S"/trivy-*.sarif; do cp "$f" "$O/vulnerabilities-$(basename "$f")"; done
for f in "$S"/grype-*.json; do [ -e "$f" ] && cp "$f" "$O/vulnerabilities-$(basename "$f")"; done
for f in "$S"/embedded-trivy-*.json "$S"/embedded-grype-*.json; do
  if [ -e "$f" ]; then cp "$f" "$O/vulnerabilities-$(basename "$f")"; fi
done
cp "$ROOT/vex/pihole.openvex.json" "$O/vex.openvex.json"
cp "$ROOT/compliance/CONTROL-MAPPING.md" "$O/control-mapping.md"
for d in "$A"/lab/lab-*/; do
  [ -f "$d/LAB-REPORT.md" ] && cp "$d/LAB-REPORT.md" "$O/lab-report-$(basename "$d" | sed 's/^lab-//').md"
done

if [ "${SKIP_PROVENANCE:-0}" != 1 ]; then
  (cd "$O" && gh attestation download "oci://$IMAGE@$DIGEST" --repo "$REPO" >/dev/null)
  mv "$O"/sha256:*.jsonl "$O/provenance.sigstore.jsonl" 2>/dev/null || mv "$O"/sha256*.jsonl "$O/provenance.sigstore.jsonl"
fi

# ---- image-digests.json: what was released, and what every upstream tag resolved to ----
# The commits and FTL hashes come from the build record inside the image
# (build-inputs.txt, copied out by scan-image.sh). The next release's
# check-upstream-drift.sh compares against them, so a moved tag is caught.
rec=$(ls "$S"/build-inputs-*.txt | head -1)
field() { awk -v c="$1" -v f="$2" '$1 == c {print $f; exit}' "$rec"; }
plats=$(for p in "$S"/platform-*.txt; do
  read -r plat dig <"$p"
  key=$(basename "$p" .txt); key=${key#platform-}
  ftl=$(awk '$1 == "ftl" {print $3}' "$S/build-inputs-$key.txt" 2>/dev/null || true)
  jq -n --arg plat "$plat" --arg dig "$dig" --arg ftl "$ftl" \
    '{platform: $plat, digest: $dig} + (if $ftl != "" then {ftl_sha256: $ftl} else {} end)'
done | jq -s .)
jq -n --arg image "$IMAGE" --arg digest "$DIGEST" --arg version "$VERSION" --arg built "$now" \
  --arg commit "${GITHUB_SHA:-local}" --arg run "$run_url" \
  --arg dt "$DOCKER_TAG" --arg dtc "$(field docker-pi-hole 3)" --arg ftl "$FTL_VERSION" \
  --arg core "$CORE_VERSION" --arg corec "$(field core 3)" --arg web "$WEB_VERSION" --arg webc "$(field web 3)" \
  --argjson plats "$plats" --arg mirrors "${MIRROR_IMAGES:-}" '
  { image: $image, mirrors: ($mirrors | split(" ") | map(select(length > 0))),
    index_digest: $digest, version: $version, built: $built,
    source: { commit: $commit, workflow_run: $run },
    upstream: { docker_pi_hole: $dt, docker_pi_hole_commit: $dtc, ftl: $ftl,
                core: $core, core_commit: $corec, web: $web, web_commit: $webc },
    platforms: $plats }' \
  >"$O/image-digests.json"

# ---- licenses.csv from one CycloneDX SBOM (same packages on every platform) ----
cdx=$(find "$S" -maxdepth 1 -name 'sbom-linux-arm64.cdx.json' | grep . || find "$S" -maxdepth 1 -name 'sbom-*.cdx.json' | sort | head -1)
{
  echo "component,version,type,licenses"
  jq -r '.components[]? | [ .name, (.version // ""), (.type // ""),
      ([.licenses[]? | (.license.id // .license.name // .expression)] | join(" OR ") | if . == "" then "NOASSERTION" else . end)
    ] | @csv' "$cdx" | sort -u
} >"$O/licenses.csv"

# ---- vulnerability-report.md ----
sev='["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]'
{
  echo "# Vulnerability report — pihole-hardened $VERSION"
  echo
  echo "- Image: \`$IMAGE@$DIGEST\`"
  echo "- Scanned: $now with Trivy $TRIVY_VERSION (gate and full report) and Grype (second-opinion gate)"
  echo "- Gate: release blocked on any HIGH or CRITICAL finding that has a fix, after VEX and \`.trivyignore\`"
  echo "- VEX statements applied: $(jq '.statements | length' "$ROOT/vex/pihole.openvex.json")"
  echo
  echo "| Platform | Critical | High | Medium | Low | Unknown | Fixable |"
  echo "|---|---|---|---|---|---|---|"
  for f in "$S"/trivy-*.json; do
    k=$(basename "$f" .json | sed 's/^trivy-//')
    jq -r --arg k "$k" --argjson sev "$sev" '[.Results[]?.Vulnerabilities[]?] as $v
      | "| \($k) | " + ($sev | map(. as $s | [$v[] | select(.Severity == $s)] | length | tostring) | join(" | "))
        + " | \([$v[] | select((.FixedVersion // "") != "")] | length) |"' "$f"
  done
  echo
  echo "## Findings"
  echo
  all=$(jq -s '[.[] | .Results[]?.Vulnerabilities[]? | {id: .VulnerabilityID, pkg: .PkgName, installed: .InstalledVersion, fixed: (.FixedVersion // ""), severity: .Severity, title: (.Title // "")}] | unique' "$S"/trivy-*.json)
  if [ "$(jq length <<<"$all")" -eq 0 ]; then
    echo "No known vulnerabilities on any platform at scan time."
  else
    echo "| ID | Package | Installed | Fixed in | Severity | Title |"
    echo "|---|---|---|---|---|---|"
    jq -r '.[] | "| \(.id) | \(.pkg) | \(.installed) | \(.fixed) | \(.severity) | \(.title | gsub("\\|"; "/") | .[0:80]) |"' <<<"$all"
  fi
  echo
  echo "## Embedded components (informational, not gated)"
  echo
  echo "Libraries compiled into the static \`pihole-FTL\` binary and the JavaScript bundled with the web interface. Package scanners cannot see them in the image; they are matched from the SBOM entries the build records. A fix can only come from a new upstream release."
  echo
  emb=$( { for f in "$S"/embedded-trivy-*.json; do [ ! -e "$f" ] || jq -c '.Results[]?.Vulnerabilities[]? | {id: .VulnerabilityID, pkg: .PkgName, installed: .InstalledVersion, fixed: (.FixedVersion // ""), severity: (.Severity | ascii_upcase), by: "Trivy"}' "$f"; done
           for f in "$S"/embedded-grype-*.json; do [ ! -e "$f" ] || jq -c '.matches[]? | {id: ((if (.vulnerability.id | startswith("GHSA-")) then ([.relatedVulnerabilities[]?.id | select(startswith("CVE-"))] | first) else null end) // .vulnerability.id), pkg: .artifact.name, installed: .artifact.version, fixed: ((.vulnerability.fix.versions // []) | join(", ")), severity: (.vulnerability.severity | ascii_upcase), by: "Grype"}' "$f"; done
         } | jq -s 'group_by([.id, .pkg]) | map(.[0] + {by: (map(.by) | unique | join(", "))})')
  if [ "$(jq length <<<"$emb")" -eq 0 ]; then
    echo "No known vulnerabilities matched."
  else
    echo "| ID | Component | Version | Fixed in | Severity | Matched by |"
    echo "|---|---|---|---|---|---|"
    jq -r '.[] | "| \(.id) | \(.pkg) | \(.installed) | \(.fixed) | \(.severity) | \(.by) |"' <<<"$emb"
  fi
  echo
  sed -n '/^## Triage/,$p' "$ROOT/vex/EMBEDDED-TRIAGE.md"
  echo
  echo "Counts depend on the vulnerability database on the scan date. Re-scan the image digest to see current status."
} >"$O/vulnerability-report.md"

# ---- VERIFY.md ----
ident="https://github.com/$REPO/.github/workflows"
cat >"$O/VERIFY.md" <<EOF
# Verifying pihole-hardened $VERSION

Requires \`cosign\` 3.x, \`curl\`, \`jq\`; \`gh\` is optional (adds the SLSA provenance check).

Quick path, from a checkout of the repository:

    scripts/verify-release.sh $REPO $VERSION

Manual steps:

    # 1. The checksum manifest was signed by this repository's release workflow
    cosign verify-blob --bundle SHA256SUMS.sigstore.json \\
      --certificate-identity "$ident/release.yml@refs/heads/main" \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
    sha256sum -c SHA256SUMS

    # 2. The image index was signed by the build workflow
    cosign verify $IMAGE@$DIGEST \\
      --certificate-identity "$ident/build.yml@refs/heads/main" \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

    # 3. SLSA build provenance (GitHub artifact attestation)
    gh attestation verify oci://$IMAGE@$DIGEST --repo $REPO \\
      --signer-workflow $REPO/.github/workflows/build.yml

    # 4. SBOM, vulnerability and VEX attestations on a platform image
    #    (platform digests are in image-digests.json)
    cosign verify-attestation --type vuln $IMAGE@<platform-digest> \\
      --certificate-identity "$ident/release.yml@refs/heads/main" \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

Always deploy by digest (\`$IMAGE@$DIGEST\`), not by tag.
EOF
if [ -n "${MIRROR_IMAGES:-}" ]; then
  {
    echo
    echo "## Registry copies"
    echo
    echo "The same index, byte for byte, is also published at:"
    echo
    for m in $MIRROR_IMAGES; do echo "- \`$m@$DIGEST\`"; done
    echo
    echo "The digest is identical, and the signatures and attestations were copied"
    echo "with the image, so every command above works with the copy's name in"
    echo "place of \`$IMAGE\`. The quick path is"
    echo "\`IMAGE_REPO=<copy> scripts/verify-release.sh $REPO $VERSION\`."
  } >>"$O/VERIFY.md"
fi

# ---- RELEASE-NOTES.md ----
lab_line() { # file -> verdict line
  local f=$1
  if [ -f "$f" ]; then
    printf '%s: %s\n' "$(basename "$f" .md | sed 's/^lab-report-//')" \
      "$(grep -m1 -oE '^\*\*(PASS|FAIL)\*\*' "$f" | tr -d '*') — core checks $(grep -m1 -E '^\| Core capabilities' "$f" | cut -d'|' -f3 | xargs), parity with upstream $(grep -m1 -E '^\| Parity' "$f" | cut -d'|' -f3 | xargs)"
  fi
}
{
  echo "Hardened rebuild of the official Pi-hole image, signed and published by GitHub Actions."
  echo
  echo "**Deploy by digest:** \`$IMAGE@$DIGEST\`"
  for m in ${MIRROR_IMAGES:-}; do echo; echo "**Also on:** \`$m@$DIGEST\` (the same signed image)"; done
  echo
  echo "| Upstream | Version |"
  echo "|---|---|"
  echo "| docker-pi-hole | $DOCKER_TAG |"
  echo "| FTL | $FTL_VERSION |"
  echo "| Core | $CORE_VERSION |"
  echo "| Web | $WEB_VERSION |"
  echo
  echo "**Platforms:** $(jq -r '[.platforms[].platform] | join(", ")' "$O/image-digests.json")"
  echo
  echo "**Vulnerabilities at release** (see vulnerability-report.md):"
  for f in "$S"/trivy-*.json; do
    jq -r --arg k "$(basename "$f" .json | sed 's/^trivy-//')" '[.Results[]?.Vulnerabilities[]?] as $v
      | "- \($k): \($v | length) total, \([$v[] | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length) high/critical"' "$f"
  done
  echo
  echo "**Functional lab** (official image vs. this image, same tests):"
  for f in "$O"/lab-report-*.md; do [ -e "$f" ] && echo "- $(lab_line "$f")"; done
  echo
  echo "**Compliance bundle:** SBOMs (SPDX, CycloneDX), vulnerability reports (Trivy, Grype, SARIF), OpenVEX, SLSA provenance, lab reports, license inventory, control mapping, signed SHA256SUMS. Verify with VERIFY.md."
  echo
  echo "This bundle is evidence for assessments (NIST SP 800-190, SSDF, CMMC Level 1 practices noted in control-mapping.md). It is not a compliance determination. Not authorized for CUI."
  echo
  echo "Built from $run_url"
} >"$O/RELEASE-NOTES.md"

# ---- checksums (signed by the workflow afterwards) ----
(cd "$O" && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name 'SHA256SUMS.*' -printf '%f\n' | sort | xargs sha256sum >SHA256SUMS)
echo "bundle: $(find "$O" -maxdepth 1 -type f | wc -l) files in $O"
