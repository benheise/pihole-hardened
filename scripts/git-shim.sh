#!/bin/sh
# Installed as /usr/bin/git in the image. The real git is left out of the
# runtime image, but /opt/pihole/updatecheck.sh (run at startup and daily by
# cron) asks git for the branch, tag and commit of the Core and Web checkouts,
# and shows "N/A" in "pihole -v" and the web UI when it gets nothing.
#
# This answers those three local queries from the record the fetch stage wrote
# to /usr/share/pihole-hardened/build-inputs.txt, keyed by the current
# directory (/etc/.pihole or the web root). "git ls-remote" prints nothing and
# exits 0, which is what the real git prints for upstream's release images
# (they look up a tag named "master", which never exists). Anything else fails,
# so a script that needs real git fails loudly instead of silently.
set -eu
RECORD=/usr/share/pihole-hardened/build-inputs.txt

component() {
  case "$PWD" in
    /etc/.pihole) echo core ;;
    */admin | */admin/) echo web ;;
    *) return 1 ;;
  esac
}

field() { # <component> <field: 2=tag, 3=commit>
  awk -v c="$1" -v f="$2" '$1 == c { print $f; exit }' "$RECORD"
}

case "${1:-} ${2:-} ${3:-}" in
  "rev-parse --abbrev-ref HEAD" | "describe --tags --always" | "rev-parse --short=8 HEAD")
    c=$(component) || { echo "fatal: not a git repository: $PWD" >&2; exit 128; }
    case "$2" in
      --abbrev-ref) echo master ;; # upstream checks release tags out on a branch named master
      --tags) field "$c" 2 ;;
      --short=8) field "$c" 3 | cut -c1-8 ;;
    esac ;;
  "ls-remote "*)
    exit 0 ;;
  *)
    echo "git: this image ships a stand-in for git that only answers updatecheck.sh's queries (pihole-hardened)" >&2
    exit 1 ;;
esac
