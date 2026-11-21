#!/usr/bin/env bash
# Tamper check for mutable upstream references. The image is built from git
# tags (Core, Web, docker-pi-hole) and a release asset (FTL) that upstream could
# move or replace without the tag name changing; a weekly rebuild would then
# ship different code under the same version, with no pull request to review.
#
# Every release records what each tag resolved to (image-digests.json). This
# compares the new build against the previous release: a tag that kept its name
# but now points at different content fails the release. A tag whose name
# changed is a version bump that went through a reviewed, CI-tested pull
# request, so its new content is accepted and becomes the next baseline.
# It also requires the per-platform builds of one release to agree with each
# other, which catches a tag moving while the matrix was building.
#
# usage: scripts/check-upstream-drift.sh <scan-dir> [previous image-digests.json]
#   <scan-dir> holds build-inputs-<platform>.txt from scripts/scan-image.sh.
#   Without a previous file, the latest release's image-digests.json is fetched
#   with "gh release download" (needs GH_TOKEN and GH_REPO or REPO); if the
#   repository has no release yet, the check passes and says so.
set -euo pipefail
S=${1:?scan dir}
PREV=${2:-}
fail=0
err() { echo "::error::$*" >&2; fail=1; }

shopt -s nullglob
files=("$S"/build-inputs-*.txt)
[ "${#files[@]}" -gt 0 ] || { echo "::error::no build-inputs-*.txt in $S" >&2; exit 1; }

# ---- 1. the platform builds must agree on every platform-independent input ----
ref=${files[0]}
for f in "${files[@]:1}"; do
  for c in core web docker-pi-hole; do
    a=$(awk -v c="$c" '$1 == c {print $2, $3}' "$ref"); b=$(awk -v c="$c" '$1 == c {print $2, $3}' "$f")
    [ "$a" = "$b" ] || err "$c differs between platform builds: '$a' ($(basename "$ref")) vs '$b' ($(basename "$f"))"
  done
  a=$(awk '$1 == "ftl" {print $2}' "$ref"); b=$(awk '$1 == "ftl" {print $2}' "$f")
  [ "$a" = "$b" ] || err "FTL version differs between platform builds: $a vs $b"
done
[ $fail -eq 0 ] && echo "ok  ${#files[@]} platform build(s) agree on Core, Web, docker-pi-hole and the FTL version"

# ---- 2. compare with the previous release ----
if [ -z "$PREV" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  repo=${GH_REPO:-${REPO:?set REPO=owner/repo or pass the previous image-digests.json}}
  # Tell "no release yet" apart from "could not ask": only the former may pass
  releases=$(gh api "repos/$repo/releases?per_page=1" --jq length) \
    || { echo "::error::could not list releases of $repo" >&2; exit 1; }
  if [ "$releases" = 0 ]; then
    echo "ok  no previous release in $repo; this build becomes the baseline"
    exit $fail
  fi
  gh release download --repo "$repo" --pattern image-digests.json --dir "$tmp" >/dev/null \
    || { echo "::error::could not download image-digests.json from the latest release of $repo" >&2; exit 1; }
  PREV="$tmp/image-digests.json"
fi
pv=$(jq -r '.version // "?"' "$PREV")

compare() { # <name> <new tag> <new content> <old tag> <old content>
  local name=$1 nt=$2 nc=$3 ot=$4 oc=$5
  if [ -z "$ot" ] || [ "$ot" = null ]; then
    echo "--  $name: previous release ($pv) did not record it; $nt@$nc becomes the baseline"
  elif [ "$nt" != "$ot" ]; then
    echo "ok  $name: $ot -> $nt (version bump; new content $nc accepted)"
  elif [ "$nc" = "$oc" ]; then
    echo "ok  $name: $nt unchanged, same content"
  else
    err "$name: tag $nt is unchanged since $pv but its content moved: $oc -> $nc. Upstream tag or asset was replaced; refusing to release until a person has reviewed it."
  fi
}

for c in core web docker-pi-hole; do
  key=${c//-/_}
  compare "$c" "$(awk -v c="$c" '$1 == c {print $2}' "$ref")" "$(awk -v c="$c" '$1 == c {print $3}' "$ref")" \
    "$(jq -r ".upstream.$key // empty" "$PREV")" "$(jq -r ".upstream.${key}_commit // empty" "$PREV")"
done
# FTL's binary differs per platform, so compare each platform with its own record
for f in "${files[@]}"; do
  key=$(basename "$f" .txt); key=${key#build-inputs-}
  plat=$(tr - / <<<"$key") # linux-arm-v7 -> linux/arm/v7
  compare "ftl ($key)" "$(awk '$1 == "ftl" {print $2}' "$f")" "$(awk '$1 == "ftl" {print $3}' "$f")" \
    "$(jq -r '.upstream.ftl // empty' "$PREV")" \
    "$(jq -r --arg p "$plat" '.platforms[] | select(.platform == $p) | .ftl_sha256 // empty' "$PREV")"
done

[ $fail -eq 0 ] && echo "PASS: no upstream reference moved since release $pv"
exit $fail
