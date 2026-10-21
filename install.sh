#!/usr/bin/env bash
#
# sky-sr203-fix installer.
#
#   curl -fsSL https://raw.githubusercontent.com/issinoho/sky-sr203-fix/main/install.sh | bash
#
# (Please read a script before piping it to a shell — this one only clones the repo and
#  starts the proxy via Docker or systemd. Nothing is sent anywhere.)
#
# Options (env vars):
#   MODE=docker|systemd|auto   install method (default: auto-detect)
#   INSTALL_DIR=/opt/sky-sr203-fix   where to clone (systemd/auto)
#   ROUTER_ADDR=192.168.0.1:80 your Sky Hub address
#   PROXY_PORT=8099            port to serve the UI on
#
set -euo pipefail

REPO="https://github.com/issinoho/sky-sr203-fix.git"
MODE="${MODE:-auto}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sky-sr203-fix}"
ROUTER_ADDR="${ROUTER_ADDR:-192.168.0.1:80}"
PROXY_PORT="${PROXY_PORT:-8099}"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have git || die "git is required."

if [ "$MODE" = auto ]; then
  if have docker && docker compose version >/dev/null 2>&1; then MODE=docker
  elif have systemctl; then MODE=systemd
  elif have python3; then MODE=foreground
  else die "need Docker, systemd, or python3."; fi
fi
say "Install method: $MODE"

clone_to() { # clone_to <dir> [sudo]
  local dir="$1" sudo="${2:-}"
  if [ -d "$dir/.git" ]; then
    say "Updating existing checkout at $dir"
    $sudo git -C "$dir" pull --ff-only
  else
    say "Cloning into $dir"
    $sudo git clone "$REPO" "$dir"
  fi
}

case "$MODE" in
  docker)
    DIR="${INSTALL_DIR}"
    # default to a user-writable dir if /opt isn't writable and not root
    if [ ! -w "$(dirname "$DIR")" ] && [ "$(id -u)" -ne 0 ]; then DIR="$HOME/sky-sr203-fix"; fi
    clone_to "$DIR"
    cd "$DIR"
    printf 'PROXY_PORT=%s\nROUTER_ADDR=%s\n' "$PROXY_PORT" "$ROUTER_ADDR" > .env
    say "Building and starting the container"
    docker compose up -d --build
    ;;
  systemd)
    SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    clone_to "$INSTALL_DIR" "$SUDO"
    say "Installing systemd unit"
    tmp="$(mktemp)"
    sed -e "s#/opt/sky-sr203-fix#${INSTALL_DIR}#g" \
        -e "s#SR203_LISTEN=0.0.0.0:8099#SR203_LISTEN=0.0.0.0:${PROXY_PORT}#" \
        -e "s#SR203_TARGET=192.168.0.1:80#SR203_TARGET=${ROUTER_ADDR}#" \
        "${INSTALL_DIR}/sr203-proxy.service" > "$tmp"
    $SUDO cp "$tmp" /etc/systemd/system/sr203-proxy.service
    rm -f "$tmp"
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now sr203-proxy.service
    $SUDO systemctl --no-pager --full status sr203-proxy.service | head -5 || true
    ;;
  foreground)
    DIR="${INSTALL_DIR}"; [ -w "$(dirname "$DIR")" ] || DIR="$HOME/sky-sr203-fix"
    clone_to "$DIR"
    say "No Docker or systemd found. Start it manually with:"
    echo "  cd $DIR && SR203_LISTEN=0.0.0.0:${PROXY_PORT} SR203_TARGET=${ROUTER_ADDR} python3 -I sr203-proxy.py"
    exit 0
    ;;
  *) die "unknown MODE: $MODE (use docker|systemd|auto)";;
esac

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; : "${IP:=<this-host-ip>}"
say "Done. Browse to:  http://${IP}:${PROXY_PORT}/"
