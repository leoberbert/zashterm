#!/bin/bash

set -euo pipefail

CONTAINER_NAME="arch-box"
PACKAGE_NAME="zashterm"
# Use fully-qualified image to avoid short-name errors (Debian/Ubuntu podman)
ARCH_IMAGE="${ARCH_IMAGE:-docker.io/library/archlinux:latest}"

log() { echo -e "[$(date +%H:%M:%S)] $*"; }

ensure_tools() {
  if command -v distrobox >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
    return
  fi

  # Detect distro (best-effort)
  . /etc/os-release
  PKG_INSTALL=""

  case "${ID_LIKE:-$ID}" in
    *debian*|*ubuntu*)
      PKG_INSTALL="sudo apt update && sudo apt install -y podman distrobox"
      ;;
    *fedora*|*rhel*|*centos*)
      PKG_INSTALL="sudo dnf install -y podman distrobox"
      ;;
    *suse*)
      PKG_INSTALL="sudo zypper install -y podman distrobox"
      ;;
    *arch*)
      PKG_INSTALL="sudo pacman -Syu --needed --noconfirm podman distrobox"
      ;;
    *)
      echo "Could not detect the distro to install podman/distrobox."
      echo "Please install podman and distrobox manually and run this script again."
      exit 1
      ;;
  esac

  log "Installing podman and distrobox..."
  eval "$PKG_INSTALL"
}

create_container() {
  if distrobox ls | grep -q "$CONTAINER_NAME"; then
    log "Container $CONTAINER_NAME already exists."
    return
  fi
  log "Creating container $CONTAINER_NAME based on $ARCH_IMAGE..."
  distrobox create --name "$CONTAINER_NAME" --image "$ARCH_IMAGE" --yes
}

install_in_container() {
  log "Setting up Arch environment and installing $PACKAGE_NAME from AUR..."
  distrobox enter "$CONTAINER_NAME" -- bash -c "
    set -euo pipefail
    sudo pacman -Syu --needed --noconfirm base-devel git

    if ! command -v yay >/dev/null 2>&1; then
      echo 'Installing yay-bin...'
      git clone https://aur.archlinux.org/yay-bin.git /tmp/yay-bin
      cd /tmp/yay-bin && makepkg -si --noconfirm
    fi

    echo 'Installing $PACKAGE_NAME...'
    yay -S --noconfirm $PACKAGE_NAME

    echo 'Exporting application to the host...'
    distrobox-export --app $PACKAGE_NAME
  "
}

log "Starting automation for $PACKAGE_NAME"
ensure_tools
create_container
install_in_container
log "Done. You can run '$PACKAGE_NAME' directly on the host."
