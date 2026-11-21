# Hardened rebuild of the official Pi-hole image.
# Mirrors pi-hole/docker-pi-hole src/Dockerfile at the tag in upstream.env,
# with these deliberate differences:
#   - FTL, Core and Web are pinned to exact release tags (no "latest" lookups
#     at build time), and the FTL binary is checked against its published .sha1
#   - build-only and interactive tools (git, binutils, wget, unzip,
#     bash-completion, PADD, nightly gdb) are left out of the runtime image;
#     a small /usr/bin/git stand-in answers the three local queries that
#     "pihole updatechecker" makes, from the build record, so versions still
#     show in "pihole -v" and the web UI
#   - repository metadata (.github, .devcontainer, package-lock.json, ...) is
#     removed from the web root: FTL serves any file with a dot in its name
#     without authentication, so upstream exposes those files to anyone who
#     can reach the web port
#   - the apk binary is removed, so ADDITIONAL_PACKAGES is not supported
#   - all setuid/setgid bits are stripped (sudo and su are only ever called
#     by root inside this image, so they still work without them)
#   - tini runs as PID 1
#   - base-layer packages are upgraded ("apk upgrade") at build time
#   - no "# syntax=" line, so builds don't pull a mutable frontend image
# The upstream startup scripts are used unchanged. The container starts as
# root by design: start.sh sets file capabilities on pihole-FTL, then drops
# to the "pihole" user with capsh before starting FTL.

# Same digest upstream 2026.10.1 pins. To avoid Docker Hub pull limits in CI,
# the identical image is available as mirror.gcr.io/library/alpine@<same digest>
# (digests are content addresses, so integrity is unchanged).
# renovate: datasource=docker depName=docker.io/library/alpine
ARG BASE_IMAGE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

# ---------- fetch: download and verify every upstream input ----------
FROM ${BASE_IMAGE} AS fetch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG TARGETPLATFORM
ARG FTL_VERSION
ARG CORE_VERSION
ARG WEB_VERSION
RUN apk add --no-cache binutils curl git
WORKDIR /src

RUN set -eu; \
    case "${TARGETPLATFORM}" in \
      linux/amd64)  A=amd64 ;; \
      linux/arm64)  A=arm64 ;; \
      linux/arm/v7) A=armv7 ;; \
      linux/arm/v6) A=armv6 ;; \
      *) echo "unsupported platform: ${TARGETPLATFORM}" >&2; exit 1 ;; \
    esac; \
    u="https://github.com/pi-hole/FTL/releases/download/${FTL_VERSION}"; \
    curl -fsSLo pihole-FTL "${u}/pihole-FTL-${A}"; \
    curl -fsSLo pihole-FTL.sha1 "${u}/pihole-FTL-${A}.sha1"; \
    echo "$(cut -d' ' -f1 pihole-FTL.sha1)  pihole-FTL" | sha1sum -c -; \
    readelf -h pihole-FTL >/dev/null; \
    chmod 0755 pihole-FTL

ARG PIHOLE_DOCKER_TAG=unknown
ARG PIHOLE_DOCKER_COMMIT=unknown
RUN set -eu; \
    git clone -q --depth 1 --branch "${CORE_VERSION}" https://github.com/pi-hole/pi-hole.git core; \
    git clone -q --depth 1 --branch "${WEB_VERSION}" https://github.com/pi-hole/web.git web; \
    curl -fsSLo macvendor.db https://ftl.pi-hole.net/macvendor.db; \
    # macvendor.db is published without a checksum; at least make sure it is a SQLite file
    [ "$(head -c 15 macvendor.db)" = "SQLite format 3" ]; \
    { echo "core ${CORE_VERSION} $(git -C core rev-parse HEAD)"; \
      echo "web ${WEB_VERSION} $(git -C web rev-parse HEAD)"; \
      echo "ftl ${FTL_VERSION} sha256:$(sha256sum pihole-FTL | cut -d' ' -f1)"; \
      echo "docker-pi-hole ${PIHOLE_DOCKER_TAG} ${PIHOLE_DOCKER_COMMIT}"; \
      echo "macvendor.db sha256:$(sha256sum macvendor.db | cut -d' ' -f1)"; \
    } > build-inputs.txt; \
    # Not needed at runtime. Everything under the web root with a dot in its
    # name is served before login (see the header comment), and Trivy would
    # report the test Dockerfiles and package-lock.json as findings in the image.
    rm -rf core/.git core/test core/.github \
           web/.git web/.github web/.devcontainer web/.gitattributes web/.gitignore \
           web/.editorconfig web/.codespellignore web/README.md web/CONTRIBUTING.md \
           web/package.json web/package-lock.json web/xo.config.js web/postcss.config.js

# ---------- runtime ----------
FROM ${BASE_IMAGE}
ARG PIHOLE_DOCKER_TAG=unknown
ARG PIHOLE_UID=1000
ARG PIHOLE_GID=1000
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

ENV DNSMASQ_USER=pihole
ENV FTL_CMD=no-daemon

# Upstream's runtime packages minus git, binutils, wget, unzip and
# bash-completion; plus tini. scripts/check-upstream-packages.sh fails CI when
# upstream adds a package that this list hasn't accounted for.
# "apk upgrade" pulls fixes for packages already in the base layer, which
# "apk add" never touches (it cleared a zlib CVE on the 3.24.3 base).
RUN apk upgrade --no-cache && \
    apk add --no-cache \
      bash bind-tools coreutils curl grep iproute2 jq libcap logrotate \
      ncurses procps-ng psmisc setpriv shadow sudo tini tzdata

COPY --from=fetch /src/core /etc/.pihole
COPY --from=fetch /src/web /var/www/html/admin
COPY --from=fetch --chmod=0755 /src/pihole-FTL /usr/bin/pihole-FTL
COPY --from=fetch /src/macvendor.db /macvendor.db
COPY --from=fetch /src/build-inputs.txt /usr/share/pihole-hardened/build-inputs.txt

# Same layout as upstream's install step
WORKDIR /etc/.pihole
RUN set -eu; \
    install -Dm755 -d /opt/pihole; \
    install -Dm755 -t /opt/pihole gravity.sh; \
    install -Dm755 -t /opt/pihole ./advanced/Scripts/*.sh; \
    install -Dm755 -t /opt/pihole ./advanced/Scripts/COL_TABLE; \
    install -Dm755 -d /etc/pihole; \
    install -Dm755 -d /var/log/pihole; \
    install -Dm755 -d /var/lib/logrotate; \
    install -Dm755 -t /usr/local/bin pihole; \
    install -T -m 0755 ./advanced/Templates/pihole-FTL-prestart.sh /opt/pihole/pihole-FTL-prestart.sh; \
    install -T -m 0755 ./advanced/Templates/pihole-FTL-poststop.sh /opt/pihole/pihole-FTL-poststop.sh; \
    install -T -m 0644 ./advanced/Templates/logrotate /etc/logrotate.d/pihole; \
    addgroup -S pihole -g "${PIHOLE_GID}"; \
    adduser -S pihole -G pihole -u "${PIHOLE_UID}"
WORKDIR /

# Upstream startup scripts, unchanged, from the checkout of the release tag
COPY --chmod=0755 upstream/src/bash_functions.sh upstream/src/prefix-time.sh upstream/src/start.sh /usr/bin/
COPY upstream/src/crontab.txt /crontab.txt
# Stand-in for git: /opt/pihole/updatecheck.sh asks git for the local branch,
# tag and commit of Core and Web. This answers from build-inputs.txt.
COPY --chmod=0755 scripts/git-shim.sh /usr/bin/git

RUN set -eu; \
    echo "${PIHOLE_DOCKER_TAG}" > /pihole.docker.tag; \
    find / -xdev -type f -perm /6000 -exec chmod a-s {} +; \
    rm -f /sbin/apk; \
    rm -rf /var/cache/apk/*
# /lib/apk/db is kept on purpose: scanners read it to inventory packages.

EXPOSE 53/tcp 53/udp 67/udp 80/tcp 123/udp 443/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK CMD ["/bin/sh", "-c", "dig -p $(pihole-FTL --config dns.port) +short +norecurse +retry=0 @127.0.0.1 pi.hole || exit 1"]

LABEL org.opencontainers.image.title="pihole-hardened" \
      org.opencontainers.image.description="Hardened rebuild of the official Pi-hole image" \
      org.opencontainers.image.version="${PIHOLE_DOCKER_TAG}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="EUPL-1.2"

ENTRYPOINT ["/sbin/tini", "--", "start.sh"]
