#!/usr/bin/env bash
set -e

echo "[*] Checking OpenSSL version..."

OPENSSL_BIN=$(command -v openssl || true)
if [[ -z "$OPENSSL_BIN" ]]; then
  echo "[!] Error: OpenSSL binary not found in PATH." >&2
  exit 1
fi

OPENSSL_VERSION=$("$OPENSSL_BIN" version | awk '{print $2}')
OPENSSL_MAJOR=$(echo "$OPENSSL_VERSION" | cut -d. -f1)
OPENSSL_MINOR=$(echo "$OPENSSL_VERSION" | cut -d. -f2)

if (( OPENSSL_MAJOR < 3 )); then
  echo "[!] Error: Detected OpenSSL version $OPENSSL_VERSION"
  echo "    This project requires OpenSSL 3.0 or newer."
  exit 1
fi

echo "[✓] Found OpenSSL $OPENSSL_VERSION at $OPENSSL_BIN"

# Candidate locations to try
PREFIX_CANDIDATES=(
  "/usr/local"
  "/opt/homebrew/opt/openssl@3"
  "/opt/openssl-3.0"
  "/usr"
)

echo "[*] Searching common prefixes for usable OpenSSL headers..."

for prefix in "${PREFIX_CANDIDATES[@]}"; do
  if [[ -f "$prefix/include/openssl/core_names.h" ]]; then
    echo "[✓] Found core_names.h in $prefix"

    echo "OPENSSL_PREFIX := $prefix" > config.mk
    echo "OPENSSL_CFLAGS := -I$prefix/include" >> config.mk

    if [[ -d "$prefix/lib64" ]]; then
      LIBDIR="$prefix/lib64"
    else
      LIBDIR="$prefix/lib"
    fi

    echo "OPENSSL_LDFLAGS := -L$LIBDIR" >> config.mk
    echo "OPENSSL_RPATH := -Wl,-rpath,$LIBDIR" >> config.mk

    echo "[+] Wrote config.mk:"
    cat config.mk
    exit 0
  fi
done

echo "[!] Could not find openssl/core_names.h in standard locations."

read -p "Would you like to run a system-wide search for core_names.h? [y/N] " do_search

if [[ "$do_search" =~ ^[Yy]$ ]]; then
  echo "[*] Searching..."
  FOUND=$(find / -type f -name core_names.h 2>/dev/null | head -n 1)

  if [[ -n "$FOUND" ]]; then
    PREFIX=$(dirname "$FOUND" | sed 's|/include/openssl||')
    echo "[✓] Found in: $FOUND (using prefix $PREFIX)"

    echo "OPENSSL_PREFIX := $PREFIX" > config.mk
    echo "OPENSSL_CFLAGS := -I$PREFIX/include" >> config.mk

    if [[ -d "$PREFIX/lib64" ]]; then
      LIBDIR="$PREFIX/lib64"
    else
      LIBDIR="$PREFIX/lib"
    fi

    echo "OPENSSL_LDFLAGS := -L$LIBDIR" >> config.mk
    echo "OPENSSL_RPATH := -Wl,-rpath,$LIBDIR" >> config.mk

    echo "[+] Wrote config.mk:"
    cat config.mk
    exit 0
  else
    echo "[!] core_names.h not found. You may need to install OpenSSL 3.x manually."
    exit 1
  fi
else
  echo "[!] Aborting. Please install OpenSSL 3.x or run a manual search for core_names.h"
  exit 1
fi
