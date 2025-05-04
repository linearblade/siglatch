# Temporary file to store installation candidates
OPENSSL_INSTALLATIONS_TMP="/tmp/openssl_installations.$$"
: > "$OPENSSL_INSTALLATIONS_TMP"

cleanup(){
    rm -rf "$OPENSSL_INSTALLATIONS_TMP"
}

# Function: find_openssl_installations

find_openssl_installations() {
  echo "Scanning system for OpenSSL library installations..."
  > "$OPENSSL_INSTALLATIONS_TMP"  # clear existing

  # Add known macOS Homebrew OpenSSL locations (if they exist)
  if [ -d "/opt/homebrew/opt/openssl@3/lib" ]; then
    echo "/opt/homebrew/opt/openssl@3/lib" >> "$OPENSSL_INSTALLATIONS_TMP"
  elif [ -d "/usr/local/opt/openssl@3/lib" ]; then
    echo "/usr/local/opt/openssl@3/lib" >> "$OPENSSL_INSTALLATIONS_TMP"
  fi

  # Standard Linux-style search for libssl + libcrypto
  find / -type f -name "libssl.so*" 2>/dev/null | while IFS= read -r ssl_path; do
    base_dir=$(dirname "$ssl_path")
    if ls "$base_dir"/libcrypto.so* >/dev/null 2>&1; then
      echo "$base_dir" >> "$OPENSSL_INSTALLATIONS_TMP"
    fi
  done

  if [ ! -s "$OPENSSL_INSTALLATIONS_TMP" ]; then
    echo "No complete OpenSSL installations found (libssl + libcrypto)."
    return 1
  else
    echo "OpenSSL installations found:"
    sort -u "$OPENSSL_INSTALLATIONS_TMP" | while IFS= read -r dir; do
      echo "  Found OpenSSL libraries in: $dir"
    done
    return 0
  fi
}

generate_linker_snippets() {
    if [ ! -s "$OPENSSL_INSTALLATIONS_TMP" ]; then
        echo "No installations to generate snippets from."
        return 1
    fi

    echo ""
    echo "Suggested compilation and linking options:"
    echo ""

    INCLUDE_TMP="/tmp/openssl_includes.$$"
    LIB_TMP="/tmp/openssl_libs.$$"
    : > "$INCLUDE_TMP"
    : > "$LIB_TMP"

    # Gather includes
    sort -u "$OPENSSL_INSTALLATIONS_TMP" | while IFS= read -r dir; do
        parent_dir=$(dirname "$dir")
        for try in "$parent_dir/include" "$parent_dir/include/openssl"; do
            if [ -d "$try" ]; then
                echo "$try" >> "$INCLUDE_TMP"
                echo "  -I$try"
                break
            fi
        done
    done

    echo ""
    echo "Linker flags (-L and -l):"
    sort -u "$OPENSSL_INSTALLATIONS_TMP" | while IFS= read -r dir; do
        echo "$dir" >> "$LIB_TMP"
        echo "  -L$dir -lssl -lcrypto"
    done

    echo ""
    echo "Runtime library path (LD_LIBRARY_PATH):"
    printf "  export LD_LIBRARY_PATH="
    sort -u "$LIB_TMP" | paste -sd: -
    echo ""

    # Generate condensed Makefile-style variables
    echo ""
    echo "You can use the following flags in your Makefile:"
    printf "  OPENSSL_CFLAGS ="
    sort -u "$INCLUDE_TMP" | while IFS= read -r inc; do
        printf " -I$inc"
    done
    echo ""

    printf "  OPENSSL_LDFLAGS ="
    sort -u "$LIB_TMP" | while IFS= read -r lib; do
        printf " -L$lib"
    done
    echo " -lssl -lcrypto"

    # Clean up
    rm -f "$INCLUDE_TMP" "$LIB_TMP"
}


 find_openssl_installations
 generate_linker_snippets
 cleanup
