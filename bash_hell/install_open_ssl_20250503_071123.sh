#!/bin/bash

OPENSSL_SITE="https://www.openssl.org/source"

check_current_version() {
  echo "🔍 Checking current OpenSSL version..."
  if command -v openssl >/dev/null 2>&1; then
    CURRENT_VERSION=$(    openssl version 2>/dev/null || /usr/local/bin/openssl version 2>/dev/null)
    echo "➡️  You are using: $CURRENT_VERSION"
  else
    echo "➡️  OpenSSL not found in PATH."
  fi
  echo ""
}

show_intro_and_select_mode() {
  echo "🚀 OpenSSL Installer"
  echo ""
  echo "ℹ️  If you can use your package manager (e.g., apt/yum/brew), that’s the best choice."
  echo "🧟  But if you're using a dusty ancient system, this script will help you compile OpenSSL from source."
  echo ""
}

fetch_openssl_versions_page(){
    if  fetch_openssl_versions_page_curl; then
	echo "lets try with wget..."
	if  fetch_openssl_versions_page_wget; then
	    return 1
	fi
    fi
    return 0
}

fetch_openssl_versions_page_curl() {
  RAW_HTML=$(curl -s "$OPENSSL_SITE")
  if [[ -z "$RAW_HTML" ]]; then
    echo "❌ Failed to fetch OpenSSL versions page. with curl"
    return 1
  fi
  return 0
}


fetch_openssl_versions_page_wget() {
  echo "🌐 Fetching available OpenSSL versions..."
  RAW_HTML=$(curl -fsSL "$OPENSSL_SITE")
  if [ $? -ne 0 ] || [ -z "$RAW_HTML" ]; then
    echo "❌ Failed to fetch OpenSSL versions page. with wget"
    return 1
  fi
  return 0
}


parse_openssl_versions() {
  VERSIONS=$(echo "$RAW_HTML" | sed -n 's/.*href="openssl-\([0-9][^"]*\)\.tar\.gz".*/\1/p' | sort -V | uniq)
  if [[ -z "$VERSIONS" ]]; then
    return 1
  fi

  echo "📦 Available versions:"
  echo "$VERSIONS"
  echo ""

  export AVAILABLE_VERSIONS="$VERSIONS"
  return 0
}

prompt_for_version() {
  DEFAULT_VERSION=$(echo "$AVAILABLE_VERSIONS" | tail -n1)
  read -p "Enter OpenSSL version to install [default: $DEFAULT_VERSION]: " CHOICE
  if [[ -z "$CHOICE" ]]; then
    CHOICE="$DEFAULT_VERSION"
  fi
  echo "📦 Selected version: $CHOICE"
  echo ""
}

download_openssl() {
  echo "⬇️  Downloading OpenSSL version $CHOICE..."
  curl -LO "$OPENSSL_SITE/openssl-$CHOICE.tar.gz"
  if [[ ! -f "openssl-$CHOICE.tar.gz" ]]; then
    echo "❌ Download failed."
    return 1
  fi
  return 0
}

get_sudo() {
  if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      return 1
    fi
  fi
  return 0
}

extract_and_build() {
  echo "📦 Extracting and building OpenSSL $CHOICE"
  tar -xf "openssl-$CHOICE.tar.gz" || return 1
  cd "openssl-$CHOICE" || return 1
  ./config --prefix=/usr/local --openssldir=/usr/local/openssl shared zlib || return 1
  make -j$(nproc) || return 1

  if get_sudo; then
    sudo make install || return 1
  else
    make install || return 1
  fi
}

# === MAIN SCRIPT ===
check_current_version
show_intro_and_select_mode

fetch_openssl_versions_page || exit 1

if ! parse_openssl_versions; then
  echo "⚠️  Unable to parse available versions."
  echo "Try visiting: $OPENSSL_SITE"
  exit 1
fi

prompt_for_version
download_openssl || exit 1

if ! get_sudo; then
  echo "⚠️  'sudo' not found and you're not root."
  read -p "Continue installation without 'sudo'? [y/N]: " CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "❌ Aborting installation."
    exit 1
  fi
fi

extract_and_build || exit 1
