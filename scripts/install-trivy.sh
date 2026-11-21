#!/usr/bin/env bash
# Install the Trivy release named in upstream.env from GitHub releases, after
# verifying the tarball against the SHA-256 pinned in upstream.env. The pin is
# deliberate: Trivy's own checksum file lives next to the tarball, so it only
# proves the download arrived intact, not that the release is the one that was
# reviewed (aquasecurity/trivy tags were force-pushed in March 2026). A version
# bump without a hash update fails here until a reviewer checks the new hash.
set -euo pipefail
# shellcheck source=/dev/null
source <(bash "$(dirname "$0")/upstream-env.sh")
command -v trivy >/dev/null && trivy --version | grep -q "Version: ${TRIVY_VERSION}$" && exit 0
case "$(uname -m)" in
  x86_64)  A=64bit; SUM=$TRIVY_SHA256_LINUX_64BIT ;;
  aarch64) A=ARM64; SUM=$TRIVY_SHA256_LINUX_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
T="trivy_${TRIVY_VERSION}_Linux-${A}.tar.gz"
B="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cd "$d"
curl -fsSLO "${B}/${T}"
echo "${SUM}  ${T}" | sha256sum -c - || {
  echo "::error::${T} does not match TRIVY_SHA256_LINUX_${A^^} in upstream.env. If this is a version bump, verify the new release and update the hash." >&2
  exit 1
}
tar xzf "$T" trivy
sudo install -m 0755 trivy /usr/local/bin/trivy
trivy --version | head -1
