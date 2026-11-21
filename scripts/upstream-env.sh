#!/usr/bin/env bash
# Print upstream.env as "export KEY=value" lines after checking its format, so
# callers never "source" it directly. Renovate writes version strings it gets
# from the upstream projects' release names into that file; a release named
# with shell metacharacters must fail here, not run.
#
# usage: source <(bash scripts/upstream-env.sh)
# Accepts only comments, blank lines and KEY=value with [A-Za-z0-9._-] values.
set -euo pipefail
f="$(dirname "${BASH_SOURCE[0]}")/../upstream.env"
bad=$(grep -nEv '^(#.*|[[:space:]]*|[A-Z][A-Z0-9_]*=[A-Za-z0-9._-]+)$' "$f" || true)
if [ -n "$bad" ]; then
  echo "upstream.env: unexpected content on line(s):" >&2
  echo "$bad" >&2
  exit 1
fi
grep -E '^[A-Z][A-Z0-9_]*=' "$f" | sed 's/^/export /'
