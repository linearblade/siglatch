#!/bin/bash

OPENSSL_SITE="https://www.openssl.org/source"
RAW_HTML=""
VERSIONS=""
CHOICE=""

show_intro_and_select_mode() {
  echo "🔍 Checking current OpenSSL version..."
  CURRENT_VERSION=$(
    openssl version 2>/dev/null ||
    /usr/local/bin/openssl version 2>/dev/null ||
    echo "None (not found)"
  )
  echo "➡️  Detected OpenSSL: $CURRENT_VERSION"
  echo

  echo "ℹ️  If you can install OpenSSL 3.x+ via your package manager, that's **strongly recommended**."
  echo "   Examples:"
  echo "     • Debian/Ubuntu:    sudo apt install openssl libssl-dev"
  echo "     • RHEL/CentOS 8+:   sudo dnf install openssl openssl-devel"
  echo "     • macOS (brew):     brew install openssl@3"
  echo
  echo "💀 But if you're on a dusty-as-hell system or can't upgrade that way, you can try one of the following:"
  echo

  echo "🛠️  Choose installation mode:"
  echo "1) 🔄 Automatic install (recommended)"
  echo "2) 🧰 DIY (show commands, do it yourself)"
  echo

  read -p "Enter your choice [1/2]: " INSTALL_MODE
  echo

  if [[ "$INSTALL_MODE" == "2" ]]; then
    echo "📋 Here's what you would run manually:"
    cat <<'EOF'
# Example DIY install steps
wget https://www.openssl.org/source/openssl-X.Y.Z.tar.gz
tar -xzf openssl-X.Y.Z.tar.gz
cd openssl-X.Y.Z
./config --prefix=/usr/local --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
EOF
    exit 0
  fi
}
get_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
  elif [ "$(id -u)" -eq 0 ]; then
    echo "🔓 Running as root. Proceeding without sudo."
    SUDO=""
  else
    echo "❌ 'sudo' is not installed and you're not root. Cannot continue installation."
    exit 1
  fi
}

check_current_version() {
  echo "🔍 Checking current OpenSSL version..."
  CURRENT=$(openssl version 2>/dev/null || echo "unknown")
  echo "➡️  You are using: $CURRENT"
  echo ""
}

fetch_openssl_versions_page() {
  echo "🌐 Fetching available OpenSSL versions..."
  RAW_HTML=$(curl -fsSL "$OPENSSL_SITE")
  if [ $? -ne 0 ] || [ -z "$RAW_HTML" ]; then
    echo "❌ Failed to fetch OpenSSL versions page."
    return 1
  fi
  return 0
}

parse_openssl_versions_grep_op() {
  VERSIONS=$(echo "$RAW_HTML" | grep -oP 'openssl-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' | sort -V | uniq)
  if [ -z "$VERSIONS" ]; then
    return 1
  fi
  return 0
}
parse_openssl_versions() {
  VERSIONS=$(echo "$RAW_HTML" \
    | grep -Eo 'href="[^"]*openssl-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz"' \
    | sed -E 's/.*openssl-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz.*/\1/' \
    | sort -V | uniq)

  if [ -z "$VERSIONS" ]; then
    return 1
  fi

  echo "📦 Available versions:"
  echo "$VERSIONS"
  echo ""

  LATEST=$(echo "$VERSIONS" | tail -n1)
  read -p "Enter OpenSSL version to install [default: $LATEST]: " CHOICE
  if [ -z "$CHOICE" ]; then
    CHOICE="$LATEST"
  fi
  echo ""
}

prompt_for_version() {
  echo "📦 Available versions:"
  echo "$VERSIONS"
  echo ""
  read -p "Enter OpenSSL version to install [default: $LATEST]: " CHOICE
  CHOICE="${CHOICE:-$LATEST}"
  echo ""
  echo "📦 Selected version: $CHOICE"
}

prompt_for_versionold() {
  echo "📦 Available versions:"
  echo "$VERSIONS"
  echo ""

  # Show prompt
  read -p "Enter OpenSSL version to install [default: $LATEST]: " CHOICE

  # Fallback to default if blank
  if [[ -z "$CHOICE" ]]; then
    CHOICE="$LATEST"
  fi

  echo "📦 Selected version: $CHOICE"
  echo ""
}

download_openssl() {
  echo "⬇️  Downloading OpenSSL version $CHOICE..."
  curl -L -O "$OPENSSL_SITE/openssl-$CHOICE.tar.gz"
  if [ ! -f "openssl-$CHOICE.tar.gz" ]; then
    echo "❌ Download failed."
    return 1
  fi
  return 0
}

extract_and_build() {
  echo "📦 Extracting and building OpenSSL $CHOICE..."
  tar -xzf "openssl-$CHOICE.tar.gz" || return 1
  cd "openssl-$CHOICE" || return 1
  ./config --prefix=/usr/local/openssl-$CHOICE || return 1
  make -j$(nproc) || return 1
  sudo make install || return 1
  echo "✅ OpenSSL $CHOICE installed successfully at /usr/local/openssl-$CHOICE"
  return 0
}

# === MAIN SCRIPT ===

#check_current_version
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
exit 1
extract_and_build || exit 1
