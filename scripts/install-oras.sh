#!/usr/bin/env bash
# Install the ORAS release named in upstream.env, verified against the SHA-256
# pinned there (same reasoning as scripts/install-trivy.sh: the checksum file
# next to a release only proves the download arrived intact).
set -euo pipefail
# shellcheck source=/dev/null
source <(bash "$(dirname "$0")/upstream-env.sh")
command -v oras >/dev/null && oras version | grep -q "^Version: *${ORAS_VERSION}$" && exit 0
case "$(uname -m)" in
  x86_64)  A=amd64; SUM=$ORAS_SHA256_LINUX_AMD64 ;;
  aarch64) A=arm64; SUM=$ORAS_SHA256_LINUX_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
T="oras_${ORAS_VERSION}_linux_${A}.tar.gz"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cd "$d"
curl -fsSLO "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/${T}"
echo "${SUM}  ${T}" | sha256sum -c - || {
  echo "::error::${T} does not match ORAS_SHA256_LINUX_${A^^} in upstream.env. If this is a version bump, verify the new release and update the hash." >&2
  exit 1
}
tar xzf "$T" oras
sudo install -m 0755 oras /usr/local/bin/oras
oras version | head -1
