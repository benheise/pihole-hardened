#!/bin/sh
# Run once at image build (see Dockerfile). Closes two places where upstream's
# container scripts let root write through a path that belongs to the
# unprivileged "pihole" user. FTL runs as that user, so these paths are what
# a compromised FTL could tamper with to reach root inside the container:
#
#  1. /crontab.txt (root's crontab): the weekly gravity job redirects its
#     output to a log in /var/log/pihole, and root's shell opens that redirect
#     before anything drops privileges. Bare-metal Pi-hole runs the same job
#     as the pihole user; this does the same by wrapping the job in setpriv.
#
#  2. bash_functions.sh, migrate_gravity(): at every start root creates
#     /etc/pihole/adlists.list with a shell redirect when it is missing. With
#     noclobber the shell opens with O_EXCL, which refuses any symlink.
#
# Found 2026-11-19. This goes to Pi-hole as a private security report, and
# the full write-up stays out of this repository until upstream has released
# a fix.
# The patches are pattern-based: when upstream changes or fixes a line, the
# pattern no longer matches and the file is left alone. The behaviour is what
# CI enforces, not the text: scripts/smoke-test.sh plants symlinks as the
# pihole user and fails if root writes through them.
#
# usage: patch-upstream.sh <crontab.txt> <bash_functions.sh>
set -eu
CRON=${1:?crontab}; FUNCS=${2:?bash_functions.sh}

# ---- 1. cron jobs that redirect into a pihole-owned directory run as pihole ----
tmp=$(mktemp)
awk '
  /^[[:space:]]*#/ || NF < 6 { print; next }
  # a job whose command redirects output into /var/log/pihole or /etc/pihole
  $0 ~ />[[:space:]]*\/(var\/log|etc)\/pihole\// && $0 !~ /setpriv/ && index($0, "\047") == 0 {
    # keep the five schedule fields exactly as written: start.sh randomizes
    # the times with sed patterns that depend on their spacing
    rest = $0; sched = ""
    for (i = 1; i <= 5; i++) {
      match(rest, /^[[:space:]]*[^[:space:]]+/)
      sched = sched substr(rest, 1, RLENGTH); rest = substr(rest, RLENGTH + 1)
    }
    sub(/^[[:space:]]+/, "", rest)
    print sched " setpriv --reuid=pihole --regid=pihole --init-groups -- sh -c \047" rest "\047"
    patched++; next
  }
  { print }
  END { printf "patch-upstream: %d cron job(s) now run as the pihole user\n", patched > "/dev/stderr" }
' "$CRON" >"$tmp"
cat "$tmp" >"$CRON"; rm -f "$tmp"

# ---- 2. root creates adlists.list only if nothing, not even a symlink, is there ----
if grep -Eq '^[[:space:]]*echo "[^"]*" >/etc/pihole/adlists\.list$' "$FUNCS"; then
  sed -i -E 's|^([[:space:]]*)(echo "[^"]*" >/etc/pihole/adlists\.list)$|\1(set -o noclobber; \2) 2>/dev/null \|\| echo "  [!] /etc/pihole/adlists.list exists as a link or could not be created; not writing through it"|' "$FUNCS"
  echo "patch-upstream: adlists.list is created with noclobber" >&2
else
  echo "patch-upstream: adlists.list redirect not found in $FUNCS (already changed upstream?)" >&2
fi
