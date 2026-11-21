#!/usr/bin/env bash
# Install pihole-hardened on this machine in one run.
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/benheise/pihole-hardened/main/deploy/install.sh)"
#   sudo bash deploy/install.sh                         # from a clone of the repository
#   sudo bash install.sh --repo benheise/pihole-hardened   # this file alone, another repository
#
# What it does, asking before every change outside its own folder:
#   1. checks the platform, the machine's own DNS and port 53
#   2. installs what is missing: curl, jq, openssl, iproute2, Docker with the compose
#      plugin, and cosign 3.x (checked against its published checksums)
#   3. puts the compose file, update.sh and verify-release.sh in /opt/pihole,
#      taking them from the clone this script sits in or, when run alone, from
#      the repository at the latest release tag
#   4. creates the admin password file and a small override file with this
#      machine's time zone
#   5. verifies the signed release, pulls the image and starts Pi-hole
#      (update.sh does this, and rolls back if the container is not healthy)
#   6. installs the daily update timer
# A Pi-hole container that already runs here (for example a Portainer stack)
# is replaced, and its data folder and password are taken over.
#
# Safe to run again: it keeps the existing password, data and override file.
#
# options:
#   --repo OWNER/REPO   GitHub repository that publishes the releases
#   --dir PATH          install folder (default /opt/pihole)
#   --yes               no questions: take the default answer to each
#   --no-timer          do not install the daily update timer
set -euo pipefail

DEFAULT_REPO="benheise/pihole-hardened"
REPO=${REPO:-}
DIR=/opt/pihole
YES=0
TIMER=1

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO=${2:?--repo needs a value}; shift 2 ;;
    --dir) DIR=${2:?--dir needs a value}; shift 2 ;;
    --yes | -y) YES=1; shift ;;
    --no-timer) TIMER=0; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

# Never stop without saying why
trap 'printf "\nSTOPPED: unexpected error at line %s of install.sh (command: %s)\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
n=0
step() { n=$((n + 1)); printf '\n[%d] %s\n' "$n" "$*"; }
ok() { printf '    ok   %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    !    %s\n' "$*" >&2; }
die() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ask "question" [y|n]  -> true for yes. --yes takes the default.
ask() {
  local def=${2:-y} hint a
  [ "$def" = y ] && hint="[Y/n]" || hint="[y/N]"
  if [ "$YES" = 1 ]; then
    printf '    ?    %s %s -> %s (--yes)\n' "$1" "$hint" "$def"
    [ "$def" = y ]; return
  fi
  [ -r /dev/tty ] || die "this step needs an answer and there is no terminal. Run again with --yes to accept the defaults."
  printf '    ?    %s %s ' "$1" "$hint" >/dev/tty
  read -r a </dev/tty || a=""
  case "${a:-$def}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- platform
[ "$(uname -s)" = Linux ] || die "this installer is for Linux."
if [ "$(id -u)" -ne 0 ]; then
  [ -f "$0" ] || die "run this as root: sudo bash install.sh"
  args=(--dir "$DIR")
  [ -n "$REPO" ] && args+=(--repo "$REPO")
  [ "$YES" = 1 ] && args+=(--yes)
  [ "$TIMER" = 0 ] && args+=(--no-timer)
  exec sudo bash "$0" "${args[@]}"
fi
case "$(uname -m)" in
  aarch64 | arm64) ARCH=arm64 ;;
  armv7l) ARCH=arm ;;
  x86_64) ARCH=amd64 ;;
  *) die "unsupported CPU '$(uname -m)'. The image is built for arm64, arm/v7 and amd64." ;;
esac
case "$DIR" in /*) ;; *) die "--dir must be an absolute path" ;; esac

step "Checking this machine"
ok "Linux on $ARCH, running as root"

# Where the deployment files come from: the clone this script is in, or GitHub
HERE=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")
SRC=""
if [ -n "$HERE" ] && [ -f "$HERE/docker-compose.yml" ] && [ -f "$HERE/update.sh" ] && [ -f "$HERE/../scripts/verify-release.sh" ]; then
  SRC=$(cd "$HERE/.." && pwd)
  ok "using the files in $SRC"
fi
if [ -z "$REPO" ] && [ "$DEFAULT_REPO" != "OWNER""/pihole-hardened" ]; then REPO=$DEFAULT_REPO; fi
if [ -z "$REPO" ] && [ -n "$SRC" ] && have git; then
  url=$(git -c safe.directory='*' -C "$SRC" remote get-url origin 2>/dev/null || true)
  REPO=$(printf '%s' "$url" | sed -n 's#.*github\.com[:/]\([^/]*/[^/]*\)$#\1#p' | sed 's/\.git$//')
fi
[ -n "$REPO" ] || die "which repository publishes the releases? Run again with --repo OWNER/REPO"
printf '%s' "$REPO" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "'$REPO' is not an OWNER/REPO name"
ok "releases come from github.com/$REPO"
IMG="ghcr.io/$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"

# ---------------------------------------------------------------- DNS of this machine
step "Checking this machine's own DNS"
resolves() { getent hosts github.com >/dev/null 2>&1; }
own_addrs=$( (ip -o addr show 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')
ns=$( (awk '$1 == "nameserver" {print $2}' /etc/resolv.conf 2>/dev/null || true) | tr '\n' ' ')
self_dns=0
for s in $ns; do
  case "$s" in 127.0.0.53) ;; # systemd-resolved's stub, handled with port 53 below
    *) case " $own_addrs " in *" $s "*) self_dns=1 ;; esac ;;
  esac
done
fix_dns() {
  have nmcli || { warn "set a DNS server by hand (for example 'nameserver 1.1.1.1' in /etc/resolv.conf) and run this again."; return 1; }
  local dev con
  dev=$( (ip route show default 2>/dev/null || true) | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  con=$(nmcli -g GENERAL.CONNECTION device show "$dev" 2>/dev/null || true)
  [ -n "$con" ] || { warn "could not find the NetworkManager connection for the default route."; return 1; }
  nmcli con mod "$con" ipv4.dns "1.1.1.1 9.9.9.9" ipv4.ignore-auto-dns yes
  nmcli con up "$con" >/dev/null
  sleep 2
  ok "connection '$con' now uses 1.1.1.1 and 9.9.9.9"
}
if resolves; then
  ok "names resolve (DNS servers: ${ns:-none listed})"
  if [ "$self_dns" = 1 ]; then
    warn "this machine uses itself as its DNS server. Whenever the Pi-hole container"
    warn "is stopped it cannot look up names, so image pulls and updates can fail."
    if ask "Point this machine's own DNS at 1.1.1.1 and 9.9.9.9 instead? (other devices are not affected)" n; then fix_dns || true; fi
  fi
else
  warn "this machine cannot resolve names (DNS servers: ${ns:-none listed})."
  [ "$self_dns" = 1 ] && warn "It uses itself as its DNS server and no Pi-hole is answering yet."
  if ask "Point this machine's own DNS at 1.1.1.1 and 9.9.9.9? (other devices are not affected)"; then fix_dns || true; fi
  resolves || die "still no DNS. Fix name resolution on this machine and run this again."
fi

# ---------------------------------------------------------------- prerequisites
step "Checking prerequisites"
cosign_ver() { cosign version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*v\{0,1\}//p'; }
cosign_ok() { have cosign && case "$(cosign_ver)" in [3-9].* | [1-9][0-9].*) true ;; *) false ;; esac; }

pkgs=""
have curl || pkgs="$pkgs curl"
have jq || pkgs="$pkgs jq"
have openssl || pkgs="$pkgs openssl"
[ -e /etc/ssl/certs/ca-certificates.crt ] || pkgs="$pkgs ca-certificates"
{ have ip && have ss; } || pkgs="$pkgs iproute2"
if [ -n "$pkgs" ]; then
  note "missing packages:$pkgs"
  have apt-get || die "install these with your package manager and run this again:$pkgs"
  ask "Install them with apt-get?" || die "these are required:$pkgs"
  apt-get update -qq
  # shellcheck disable=SC2086  # word splitting wanted: a list of package names
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs >/dev/null
fi
ok "curl, jq, openssl, iproute2"

if ! have docker; then
  note "Docker is not installed."
  ask "Install Docker with Docker's official script (https://get.docker.com)?" || die "Docker is required."
  t=$(mktemp)
  curl -fsSL https://get.docker.com -o "$t"
  sh "$t" >/dev/null
  rm -f "$t"
fi
if ! docker info >/dev/null 2>&1; then
  have systemctl && systemctl start docker >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || die "Docker is installed but its service is not running. Start it (sudo systemctl start docker) and run this again."
fi
if ! docker compose version >/dev/null 2>&1; then
  note "Docker's compose plugin is missing."
  have apt-get || die "install the Docker compose plugin and run this again."
  ask "Install it with apt-get (docker-compose-plugin)?" || die "the compose plugin is required."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 ||
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 ||
    die "could not install the compose plugin. See https://docs.docker.com/compose/install/linux/"
fi
ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) with compose $(docker compose version --short 2>/dev/null)"

if ! cosign_ok; then
  if have cosign; then note "cosign $(cosign_ver) is too old: releases are signed in cosign 3's format."
  else note "cosign is not installed (it verifies the release signatures)."; fi
  ask "Download the current cosign from github.com/sigstore/cosign and install it to /usr/local/bin?" || die "cosign 3.x is required."
  t=$(mktemp -d)
  base=https://github.com/sigstore/cosign/releases/latest/download
  curl -fsSL -o "$t/cosign-linux-$ARCH" "$base/cosign-linux-$ARCH" || die "could not download cosign."
  curl -fsSL -o "$t/cosign_checksums.txt" "$base/cosign_checksums.txt" || die "could not download cosign's checksums."
  (cd "$t" && grep " cosign-linux-$ARCH\$" cosign_checksums.txt | sha256sum -c - >/dev/null) ||
    die "the downloaded cosign does not match its published checksum. Nothing was installed."
  install -m 0755 "$t/cosign-linux-$ARCH" /usr/local/bin/cosign
  rm -rf "$t"
  hash -r
  cosign_ok || die "cosign was installed but 'cosign version' does not report 3.x or newer."
fi
ok "cosign $(cosign_ver)"

# ---------------------------------------------------------------- port 53 and an existing Pi-hole
step "Checking port 53 and for an existing Pi-hole"
OLD=none OLD_DATA="" OLD_DATA_TYPE="" OLD_PW=""
if docker inspect pihole >/dev/null 2>&1; then
  wd=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' pihole 2>/dev/null || true)
  if [ "$wd" = "$DIR" ]; then
    OLD=ours
    ok "a Pi-hole installed in $DIR is already here; it will be updated in place"
  else
    OLD=foreign
    OLD_DATA=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/pihole"}}{{.Source}}{{end}}{{end}}' pihole)
    OLD_DATA_TYPE=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/pihole"}}{{.Type}}{{end}}{{end}}' pihole)
    OLD_PW=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/webpassword"}}{{.Source}}{{end}}{{end}}' pihole)
    note "a container named 'pihole' already exists:"
    note "  image  $(docker inspect -f '{{.Config.Image}}' pihole)"
    note "  data   ${OLD_DATA:-not kept outside the container}"
    [ -n "$wd" ] && note "  started from $wd"
    ask "Replace it with the release from $REPO, keeping its data and password?" ||
      die "left the existing container alone. Nothing was changed in $DIR."
  fi
fi
if [ "$OLD" = none ]; then
  listening=$(ss -Hlntu 'sport = :53' 2>/dev/null || true)
  users=$( (ss -Hlntup 'sport = :53' 2>/dev/null || true) | (grep -o 'users:(("[^"]*"' || true) | cut -d'"' -f2 | sort -u | tr '\n' ' ')
  if [ -n "$listening" ]; then
    [ -n "$users" ] || users="an unidentified process "
    case " $users " in
      *" systemd-resolve"*)
        note "systemd-resolved's stub listener holds port 53."
        ask "Turn the stub listener off (DNSStubListener=no) and restart systemd-resolved?" ||
          die "port 53 must be free for Pi-hole."
        mkdir -p /etc/systemd/resolved.conf.d
        printf '[Resolve]\nDNSStubListener=no\n' >/etc/systemd/resolved.conf.d/pihole-hardened.conf
        [ -e /run/systemd/resolve/resolv.conf ] && ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        systemctl restart systemd-resolved
        sleep 1
        resolves || die "name resolution stopped working after that change. Check /etc/resolv.conf."
        ;;
      *) die "port 53 is in use by: $users. Stop that service (it would conflict with Pi-hole) and run this again." ;;
    esac
  fi
  ok "port 53 is free"
fi

# ---------------------------------------------------------------- files
step "Installing files into $DIR"
install -d -m 0755 "$DIR"
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
if [ -n "$SRC" ]; then
  cp "$SRC/deploy/docker-compose.yml" "$SRC/deploy/update.sh" "$SRC/scripts/verify-release.sh" \
    "$SRC/deploy/pihole-update.service" "$SRC/deploy/pihole-update.timer" "$TMPD/"
else
  rel="https://github.com/$REPO/releases/latest/download"
  tag=$(curl -fsSL "$rel/image-digests.json" | jq -r .version) || die "could not read the latest release of $REPO. Is the repository public and does it have a release?"
  printf '%s' "$tag" | grep -Eq '^[A-Za-z0-9._-]+$' || die "unexpected release name '$tag'"
  raw="https://raw.githubusercontent.com/$REPO/$tag"
  for f in deploy/docker-compose.yml deploy/update.sh scripts/verify-release.sh deploy/pihole-update.service deploy/pihole-update.timer; do
    curl -fsSL -o "$TMPD/$(basename "$f")" "$raw/$f" || die "could not download $f from $raw"
  done
  note "files taken from $REPO at release $tag"
fi
sed -i "s#benheise/pihole-hardened#$REPO#g" "$TMPD/docker-compose.yml"
install -m 0644 "$TMPD/docker-compose.yml" "$DIR/docker-compose.yml"
install -m 0755 "$TMPD/update.sh" "$DIR/update.sh"
install -m 0755 "$TMPD/verify-release.sh" "$DIR/verify-release.sh"
ok "docker-compose.yml, update.sh, verify-release.sh"

NEW_PW=0
if [ -s "$DIR/webpassword" ]; then
  ok "keeping the existing admin password ($DIR/webpassword)"
elif [ -n "$OLD_PW" ] && [ -s "$OLD_PW" ]; then
  install -m 0600 "$OLD_PW" "$DIR/webpassword"
  ok "took over the admin password from $OLD_PW"
else
  (umask 077 && openssl rand -base64 24 >"$DIR/webpassword")
  NEW_PW=1
  ok "generated an admin password ($DIR/webpassword, readable by root only)"
fi
chmod 600 "$DIR/webpassword"

tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
[ -n "$tz" ] || tz=$(cat /etc/timezone 2>/dev/null || true)
[ -n "$tz" ] || tz=$( (readlink /etc/localtime 2>/dev/null || true) | sed -n 's#.*/zoneinfo/##p')
[ -n "$tz" ] || tz=UTC
DATA="$DIR/etc-pihole"

# ---------------------------------------------------------------- registry access
step "Checking access to $IMG"
[ -d "$DIR/.docker" ] && export DOCKER_CONFIG="$DIR/.docker"
if docker manifest inspect "$IMG:latest" >/dev/null 2>&1; then
  ok "the image can be pulled"
else
  warn "cannot read $IMG. The package is probably still private"
  warn "(GitHub: your profile > Packages > pihole-hardened > Package settings > Change visibility)."
  if [ "$YES" = 1 ] || ! [ -r /dev/tty ]; then die "make the package public, or run this again without --yes to log in."; fi
  ask "Log in to ghcr.io now with a GitHub token that has read:packages? (stored in $DIR/.docker, readable by root only)" ||
    die "make the package public and run this again."
  printf '         GitHub username: ' >/dev/tty; read -r gh_user </dev/tty
  printf '         Token (not shown): ' >/dev/tty; read -rs gh_token </dev/tty; echo >/dev/tty
  install -d -m 0700 "$DIR/.docker"
  export DOCKER_CONFIG="$DIR/.docker"
  printf '%s' "$gh_token" | docker login ghcr.io -u "$gh_user" --password-stdin >/dev/null 2>&1 || die "login to ghcr.io failed."
  unset gh_token
  docker manifest inspect "$IMG:latest" >/dev/null 2>&1 || die "logged in, but $IMG still cannot be read. Does the token have read:packages?"
  ok "logged in to ghcr.io"
fi

# ---------------------------------------------------------------- verify and pull before touching anything
if [ "$OLD" = ours ]; then
  ref="" ver=""   # update.sh verifies, pulls and replaces in one go below
else
step "Verifying the signed release and pulling the image"
out=$("$DIR/verify-release.sh" "$REPO" latest 2>"$TMPD/verify.log") || { sed 's/^/    /' "$TMPD/verify.log" >&2; die "the release did not verify. Nothing was started or replaced."; }
grep '^ok' "$TMPD/verify.log" | sed 's/^/    /' || true
ref=$(printf '%s\n' "$out" | tail -1)
ver=$(printf '%s\n' "$out" | sed -n 's/^version //p')
docker pull -q "$ref" >/dev/null || die "could not pull $ref"
ok "release $ver verified and pulled"
fi

# ---------------------------------------------------------------- take over an existing container
# The old container is only stopped and renamed here. It is removed after the
# new one is healthy, and put back (with its data) if the new one is not.
MOVED=0
rollback_old() {
  [ "$OLD" = foreign ] || return 0
  warn "putting the previous container back"
  (cd "$DIR" && docker compose down >/dev/null 2>&1) || true
  if [ "$MOVED" = 1 ]; then mv "$DIR/etc-pihole" "$OLD_DATA"; fi
  docker rename pihole-replaced pihole >/dev/null 2>&1 || true
  docker start pihole >/dev/null 2>&1 || true
}
if [ "$OLD" = foreign ]; then
  step "Replacing the existing container"
  docker stop pihole >/dev/null
  docker rm -f pihole-replaced >/dev/null 2>&1 || true
  docker rename pihole pihole-replaced
  if [ "$OLD_DATA" != "$DATA" ]; then
    if [ -e "$DATA" ] && [ -n "$(ls -A "$DATA" 2>/dev/null)" ]; then
      warn "$DATA already has content; the old container's data (${OLD_DATA:-inside the container}) is not used."
    elif [ "$OLD_DATA_TYPE" = bind ] && ask "Move its data from $OLD_DATA to $DATA? (no: keep using it where it is)"; then
      rmdir "$DATA" 2>/dev/null || true
      mv "$OLD_DATA" "$DATA"
      MOVED=1
      ok "data moved to $DATA"
    elif [ "$OLD_DATA_TYPE" = bind ]; then
      DATA=$OLD_DATA
      ok "data stays in $DATA"
    else
      install -d "$DATA"
      docker cp -a pihole-replaced:/etc/pihole/. "$DATA/"
      ok "data copied out of the old container to $DATA"
    fi
  fi
fi

if [ -e "$DIR/docker-compose.override.yml" ]; then
  ok "keeping the existing docker-compose.override.yml"
else
  {
    echo "# Written by install.sh: settings of this machine. Docker Compose reads this"
    echo "# file together with docker-compose.yml, and updates never overwrite it."
    echo "services:"
    echo "  pihole:"
    echo "    environment:"
    echo "      TZ: \"$tz\""
    if [ "$DATA" != "$DIR/etc-pihole" ]; then
      echo "    volumes:"
      echo "      - $DATA:/etc/pihole"
    fi
  } >"$DIR/docker-compose.override.yml"
  ok "docker-compose.override.yml (time zone $tz)"
fi

# ---------------------------------------------------------------- start
step "Starting Pi-hole"
set_kv() { # KEY value, in $DIR/.env
  if grep -q "^$1=" "$DIR/.env" 2>/dev/null; then sed -i "s|^$1=.*|$1=$2|" "$DIR/.env"; else echo "$1=$2" >>"$DIR/.env"; fi
}
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' pihole 2>/dev/null || echo missing; }
wait_healthy() {
  local s=starting
  for _ in $(seq 60); do
    s=$(health)
    case "$s" in healthy | unhealthy) break ;; esac
    sleep 5
  done
  echo "$s"
}
touch "$DIR/.env"
chmod 600 "$DIR/.env"
set_kv PIHOLE_REPO "$REPO"
if [ "$OLD" = ours ]; then
  # An install that is already running: update.sh replaces it and rolls back by itself
  if ! REPO="$REPO" PIHOLE_DIR="$DIR" "$DIR/update.sh" 2>&1 | sed 's/^/    /'; then
    die "the update did not go through; update.sh's message is above. The previous version keeps running."
  fi
  [ "$(health)" = healthy ] || (cd "$DIR" && docker compose up -d pihole >/dev/null 2>&1) || true
  ver=$(sed -n 's/^PIHOLE_VERSION=//p' "$DIR/.env")
else
  # The release was verified and pulled above; start exactly that digest
  set_kv PIHOLE_IMAGE "$ref"
  set_kv PIHOLE_VERSION "$ver"
  if ! (cd "$DIR" && docker compose config -q && docker compose up -d pihole >/dev/null 2>"$TMPD/up.log"); then
    grep -v '^ *\(Network\|Container\) [^ ]* \(Creating\|Created\|Starting\) *$' "$TMPD/up.log" | tail -3 | cut -c1-400 | sed 's/^/    /' >&2 || true
    rollback_old
    die "could not start the container."
  fi
fi
status=$(wait_healthy)
if [ "$status" != healthy ]; then
  docker logs --tail 15 pihole 2>&1 | sed 's/^/    /' >&2 || true
  rollback_old
  die "the new container is '$status' (its last log lines are above)."
fi
ok "Pi-hole $ver is running and healthy"
if [ "$OLD" = foreign ]; then
  docker rm pihole-replaced >/dev/null
  ok "old container removed"
  note "If it was a Portainer stack, delete that stack in Portainer; it no longer has a container."
fi

# ---------------------------------------------------------------- timer
if [ "$TIMER" = 1 ]; then
  step "Daily automatic updates"
  if [ -d /run/systemd/system ] && have systemctl; then
    if ask "Install the timer that checks for a new verified release every night at about 04:30?"; then
      sed -e "s|^Environment=REPO=.*|Environment=REPO=$REPO|" -e "s|/opt/pihole|$DIR|g" "$TMPD/pihole-update.service" >/etc/systemd/system/pihole-update.service
      install -m 0644 "$TMPD/pihole-update.timer" /etc/systemd/system/pihole-update.timer
      systemctl daemon-reload
      systemctl enable --now pihole-update.timer >/dev/null 2>&1
      ok "pihole-update.timer enabled (see: systemctl list-timers pihole-update.timer)"
    else
      note "skipped. Update by hand with: sudo $DIR/update.sh"
    fi
  else
    note "no systemd here, so no timer. Update by hand with: sudo $DIR/update.sh"
  fi
fi

# ---------------------------------------------------------------- summary
addr=$( (ip route get 1.1.1.1 2>/dev/null || true) | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
echo
echo "Done. Pi-hole $ver is running."
echo
echo "  DNS server for your network:  ${addr:-the address of this machine}   (set it in your router's DHCP settings)"
echo "  Admin page:                   https://127.0.0.1:8443/admin   (on this machine only)"
echo "      from another computer:    ssh -L 8443:127.0.0.1:8443 <user>@${addr:-<this machine>}"
echo "                                then open https://localhost:8443/admin"
if [ "$NEW_PW" = 1 ]; then
  echo "  Admin password:               $(cat "$DIR/webpassword")"
  echo "                                (shown once; it is kept in $DIR/webpassword)"
else
  echo "  Admin password:               sudo cat $DIR/webpassword"
fi
echo "  Files:                        $DIR   (data in $DATA)"
echo "  Update now:                   sudo $DIR/update.sh"
echo "  Check a release yourself:     $DIR/verify-release.sh $REPO latest"
