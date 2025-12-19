#!/bin/bash

set -euo pipefail

CONTAINER_NAME="arch-box"
PACKAGE_NAME="zashterm"
ARCH_IMAGE="archlinux:latest"

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
      echo "Não foi possível detectar a distro para instalar podman/distrobox."
      echo "Instale manualmente podman e distrobox e execute novamente."
      exit 1
      ;;
  esac

  log "Instalando podman e distrobox..."
  eval "$PKG_INSTALL"
}

create_container() {
  if distrobox ls | grep -q "$CONTAINER_NAME"; then
    log "Container $CONTAINER_NAME já existe."
    return
  fi
  log "Criando container $CONTAINER_NAME baseado em $ARCH_IMAGE..."
  distrobox create --name "$CONTAINER_NAME" --image "$ARCH_IMAGE" --yes
}

install_in_container() {
  log "Configurando ambiente Arch e instalando $PACKAGE_NAME via AUR..."
  distrobox enter "$CONTAINER_NAME" -- bash -c "
    set -euo pipefail
    sudo pacman -Syu --needed --noconfirm base-devel git

    if ! command -v yay >/dev/null 2>&1; then
      echo 'Instalando yay-bin...'
      git clone https://aur.archlinux.org/yay-bin.git /tmp/yay-bin
      cd /tmp/yay-bin && makepkg -si --noconfirm
    fi

    echo 'Instalando $PACKAGE_NAME...'
    yay -S --noconfirm $PACKAGE_NAME

    echo 'Exportando aplicativo para o host...'
    distrobox-export --app $PACKAGE_NAME
  "
}

log "Iniciando automação para $PACKAGE_NAME"
ensure_tools
create_container
install_in_container
log "Concluído. Você pode rodar '$PACKAGE_NAME' diretamente no host."
