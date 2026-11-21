#!/usr/bin/env bash
# Compare upstream's runtime apk package list with this repo's Dockerfile.
# Fails when upstream installs a package that this image neither installs nor
# deliberately excludes, so an automated upstream bump can't silently drop a
# runtime dependency (for example, upstream master added setpriv after
# 2026.10.1).
#
# usage: scripts/check-upstream-packages.sh [upstream-Dockerfile] [our-Dockerfile]
set -euo pipefail
cd "$(dirname "$0")/.."
UPSTREAM="${1:-upstream/src/Dockerfile}"
OURS="${2:-Dockerfile}"

# Left out on purpose. Keep the reasons current; README documents each one.
#   bash-completion  interactive shell nicety
#   binutils         readelf is only needed at build time (fetch stage)
#   git              replaced by scripts/git-shim.sh, which answers updatecheck.sh
#                    from the build record (versions still show in the UI)
#   unzip, wget      not used by Core v6 scripts; busybox wget remains
EXCLUDED="bash-completion binutils git unzip wget"

# Print the packages from the first multi-line "apk add --no-cache \" block.
apk_list() {
  awk '
    !inblock && /apk add --no-cache[[:space:]]*\\[[:space:]]*$/ { inblock = 1; next }
    inblock {
      if ($0 ~ /^[[:space:]]*#/) next
      last = ($0 !~ /\\[[:space:]]*$/)
      line = $0; gsub(/\\/, "", line)
      n = split(line, w, /[[:space:]]+/)
      for (i = 1; i <= n; i++) if (w[i] != "") print w[i]
      if (last) exit
    }' "$1" | sort -u
}

up=$(apk_list "$UPSTREAM")
ours=$(apk_list "$OURS")
[ -n "$up" ] || { echo "could not parse the apk list in $UPSTREAM" >&2; exit 2; }
[ -n "$ours" ] || { echo "could not parse the apk list in $OURS" >&2; exit 2; }

missing=""
for p in $up; do
  grep -qx "$p" <<<"$ours" && continue
  case " $EXCLUDED " in *" $p "*) continue ;; esac
  missing+="$p "
done

extra=$(comm -13 <(echo "$up") <(echo "$ours") | tr '\n' ' ')
echo "upstream packages: $(echo "$up" | wc -l), ours: $(echo "$ours" | wc -l)"
echo "added here (not upstream): ${extra:-none}"

if [ -n "$missing" ]; then
  echo "::error::upstream installs packages this image neither includes nor excludes: $missing"
  echo "Add each one to the Dockerfile apk list, or to EXCLUDED with a reason."
  exit 1
fi
echo "OK: every upstream runtime package is included or deliberately excluded"
