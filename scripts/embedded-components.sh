#!/bin/sh
# Run in the Dockerfile's fetch stage. Prints the components that package
# scanners cannot see, one per line, for build-inputs.txt:
#
#   ftl-embedded <name> <version>   libraries compiled into the static
#                                   pihole-FTL binary (dnsmasq, SQLite, Lua,
#                                   CivetWeb, Mbed TLS, nettle, cJSON, ...)
#   web-vendor <name> <version>     JavaScript/CSS libraries bundled in the
#                                   web interface's vendor/ directory
#
# scripts/sbom-add-pihole.py turns these lines into SBOM components with CPEs
# and package URLs, so CVE matching works for them (a known SQLite, dnsmasq or
# Bootstrap CVE would otherwise never show up in a scan of this image).
#
# The FTL versions come from the binary itself ("pihole-FTL -vv"), which runs
# here because the fetch stage is built for the target platform. Nothing in
# this script is fatal: a version it cannot find is reported as "unknown".
#
# usage: embedded-components.sh <pihole-FTL> <web-dir>
FTL=${1:?pihole-FTL binary}; WEB=${2:?web directory}

vv=$("$FTL" -vv 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g') || vv=""
section_version() { # <section name as printed between the asterisks>
  printf '%s\n' "$vv" | awk -v s="$1" '
    /^\*+ .* \*+$/ { gsub(/^\*+ | \*+$/, ""); cur = $0; next }
    cur == s && /^Version:/ { sub(/^Version:[[:space:]]*/, ""); print; exit }'
}
emit() { # <kind> <name> <version>
  v=$(printf '%s' "$3" | tr -d '\r' | awk '{print $1}')
  printf '%s %s %s\n' "$1" "$2" "${v:-unknown}"
}

emit ftl-embedded dnsmasq "$(section_version dnsmasq)"
emit ftl-embedded sqlite "$(section_version SQLite3)"
emit ftl-embedded lua "$(section_version LUA | sed 's/^Lua //')"
emit ftl-embedded nettle "$(section_version LIBNETTLE)"
civet=$(section_version CivetWeb)
emit ftl-embedded civetweb "$civet"
emit ftl-embedded mbedtls "$(printf '%s' "$civet" | sed -n 's/.*mbed TLS \([0-9][0-9.]*\).*/\1/p')"
emit ftl-embedded cjson "$(section_version cJSON)"
# not printed by -vv; taken from version strings in the binary
bin=$(strings -n 6 "$FTL" 2>/dev/null) || bin=""
emit ftl-embedded tf-psa-crypto "$(printf '%s\n' "$bin" | sed -n 's/.*TF-PSA-Crypto \([0-9][0-9.]*\).*/\1/p' | head -1)"

# ---- bundled web libraries: version from each file's banner ----
for dir in "$WEB"/vendor/*/; do
  name=$(basename "$dir")
  case "$name" in fonts | js-warn) continue ;; esac
  f=$(find "$dir" -maxdepth 2 \( -name '*.min.js' -o -name '*.js' \) | sort | head -1)
  [ -n "$f" ] || f=$(find "$dir" -maxdepth 2 -name '*.css' | sort | head -1)
  [ -n "$f" ] || { emit web-vendor "$name" unknown; continue; }
  case "$name" in
    datatables) v=$(head -c 2000 "$f" | sed -n 's/.*DataTables \([0-9][0-9.]*[0-9]\).*/\1/p' | head -1) ;;
    moment) v=$(grep -o 'version="[0-9][0-9.]*"' "$f" | head -1 | tr -dc '0-9.') ;;
    select2) v=$(head -c 400 "$f" | sed -n 's/.*Select2 \([0-9][0-9.]*[0-9]\).*/\1/p' | head -1) ;;
    *) v=$(head -c 3000 "$f" | grep -oiE '(v|version:? ?|@version ?)[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?') ;;
  esac
  emit web-vendor "$name" "$v"
done
