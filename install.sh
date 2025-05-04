#!/bin/bash

set -e

CONFIG_DIR="/etc/siglatch"
KEY_FILE="$CONFIG_DIR/server_priv.pem"
CONFIG_FILE="$CONFIG_DIR/server.conf"
DEFAULT_CONFIG="./default_config/server.conf"

function is_macos() {
    [[ "$(uname)" == "Darwin" ]]
}

function do_chown() {
    if is_macos; then
        chown root "$1"
    else
        chown root:root "$1"
    fi
}

construct_install_dirs() {
  echo "📦 Creating Siglatch install directories..."

  local base="/etc/siglatch"
  local scripts_dir="$base/scripts"
  local log_dir="/var/log/siglatch"
  local state_dir="/var/lib/siglatch"

  # Create base directories
  mkdir -p "$scripts_dir"
  mkdir -p "$log_dir"
  mkdir -p "$state_dir"

  # Create symlinks inside /etc/siglatch
  ln -snf "$log_dir" "$base/logs"
  ln -snf "$state_dir" "$base/state"

  # Copy core daemon binary
  cp ./siglatchd "$base/" || {
    echo "❌ Failed to copy siglatchd"
    return 1
  }

  # Place `knocker` into system binary path
  # Recommend: /usr/local/bin (not /etc)
  cp ./knocker /usr/local/bin/knocker || {
    echo "❌ Failed to install knocker"
    return 1
  }
  chmod +x /usr/local/bin/knocker

  echo "✅ Install directories and binaries set up successfully."
}
validate_key() {
    echo "🔍 Validating private key at $KEY_FILE..."

    if [ ! -f "$KEY_FILE" ]; then
        echo "❌ Key file does not exist: $KEY_FILE"
        return 1
    fi

    # Check if it's a valid RSA private key
    if openssl rsa -in "$KEY_FILE" -check -noout > /dev/null 2>&1; then
        echo "✅ RSA private key is valid."
        # Show fingerprint or key info
        openssl rsa -in "$KEY_FILE" -pubout -outform PEM | openssl rsa -pubin -pubout -text -noout | grep 'Modulus\|Exponent'
    else
        echo "❌ Invalid RSA private key or wrong format."
        return 1
    fi
}

validate_permissions() {
    echo "🔍 Validating permissions on $KEY_FILE..."

    if [ ! -f "$KEY_FILE" ]; then
        echo "❌ Key file does not exist: $KEY_FILE"
        return 1
    fi

    # Check permissions (should be 600)
    perms=$(stat -f "%Lp" "$KEY_FILE" 2>/dev/null || stat -c "%a" "$KEY_FILE")
    if [ "$perms" != "600" ]; then
        echo "❌ Incorrect permissions: expected 600, got $perms"
        return 1
    fi

    # Check ownership
    owner=$(stat -f "%Su" "$KEY_FILE" 2>/dev/null || stat -c "%U" "$KEY_FILE")
    group=$(stat -f "%Sg" "$KEY_FILE" 2>/dev/null || stat -c "%G" "$KEY_FILE")

    if [ "$owner" != "root" ]; then
        echo "❌ File must be owned by root. Found owner: $owner"
        return 1
    fi

    if is_macos && [ "$group" != "wheel" ]; then
        echo "❌ Group should be 'wheel' on macOS. Found: $group"
        return 1
    elif ! is_macos && [ "$group" != "root" ]; then
        echo "❌ Group should be 'root' on Linux. Found: $group"
        return 1
    fi

    echo "✅ Permissions and ownership are valid."
}

function install_config() {
    echo "📄 Installing default config..."
    cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
}

function generate_key() {
    echo "🔑 Generating RSA private key..."
    openssl genpkey -algorithm RSA -out "$KEY_FILE" -pkeyopt rsa_keygen_bits:2048
    chmod 600 "$KEY_FILE"
    do_chown "$KEY_FILE"
}

create_userhmac() {
    local username="$1"
    local force="$2"

    if [ -z "$username" ]; then
        echo "❌ Usage: create_userhmac <username> [--force]"
        exit 1
    fi

    local hmac_file="$CONFIG_DIR/keys/${username}.hmac.key"

    if [ -f "$hmac_file" ]; then
        if [ "$force" != "--force" ]; then
            echo "⚠️  HMAC key already exists for user '$username'. Use --force to overwrite."
            exit 1
        else
            echo "⚠️  Overwriting existing HMAC key for '$username'..."
        fi
    fi

    echo "🔐 Generating HMAC key for user '$username'..."

    # Generate random 32-byte HMAC key
    openssl rand -out "$hmac_file" 32
    chmod 600 "$hmac_file"
    do_chown "$hmac_file"

    echo "✅ HMAC key created:"
    echo "   🔒 HMAC Key: $hmac_file"
}

export_userhmac() {
    local username="$1"

    if [ -z "$username" ]; then
        echo "❌ Usage: export_userhmac <username>"
        exit 1
    fi

    local hmac_file="$CONFIG_DIR/keys/${username}.hmac.key"

    if [ ! -f "$hmac_file" ]; then
        echo "❌ HMAC key for user '$username' does not exist."
        exit 1
    fi

    echo "📤 Exporting HMAC key for user '$username':"
    cat "$hmac_file" | xxd -p
}

show_help() {
    cat <<EOF

🔐 siglatch install script — secure daemon key + config bootstrap

Usage:
  sudo ./install.sh <command> [options]

Core Commands:
  install               One-time install. Fails if already present.
  reinstall             Replaces config and regenerates server key.
  new_key               Generates a new server private key.
  repair_key            Fixes permissions and validates existing key.
  help                  Show this help message.

Key Management:
  export_pubkey         Output the server's public key (for client config)
  create_userkey <user> Generate a new RSA keypair for a user
  export_userkey <user> Output a user's private key (e.g. for email)
  install_userkey <user> [file] [--overwrite]
                        Install a user public key from file or prompt
  install_ip_auth       installs the ip auth scripts into siglatch installation
  create_userhmac <user> [--force]
                        Generate a new random HMAC key for a user
  export_userhmac <user>
                        Output a user's HMAC key (hex encoded for client use)

Configuration Note:
- After installing a user key, be sure to update your config with an entry like:

  [user:your_username_here]
  enabled = yes
  key_file = /etc/siglatch/keys/root.key
  hmac_file = /etc/siglatch/keys/root.hmac.key
  actions = grant_ip, run_script

Notes:
- This script must be run as root.
- Config will be created in /etc/siglatch/
- Keys are stored in /etc/siglatch/keys/
- All PEM and HMAC files must be mode 600 and root-owned

EOF
    exit 0
}


do_repair_key() {
    if [ -f "$KEY_FILE" ]; then
        echo "🔧 Repairing permissions for existing key..."
        chmod 600 "$KEY_FILE"
        do_chown "$KEY_FILE"
        echo "✅ Key permissions repaired."
        validate_permissions
        validate_key
    else
        echo "❌ No key found to repair at $KEY_FILE."
        exit 1
    fi
}

do_new_key() {
    echo "🗝️  Forcing new private key generation..."
    generate_key
    validate_permissions
    validate_key
}

do_reinstall() {
    echo "♻️  Reinstalling config and regenerating key..."
    mkdir -p "$CONFIG_DIR"
    construct_install_dirs
    install_config
    install_ipauth_scripts
    generate_key
    validate_permissions
    validate_key
}

do_install() {
    if [ -d "$CONFIG_DIR" ]; then
        echo "⚠️  $CONFIG_DIR already exists. Use reinstall or other options."
        show_help
        exit 1
    fi
    echo "📁 Creating $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR"
    construct_install_dirs
    install_config
    install_ipauth_scripts
    generate_key
    validate_permissions
    validate_key
}

export_pubkey() {
    echo "🔓 Exporting server public key..."

    if [ ! -f "$KEY_FILE" ]; then
        echo "❌ Server private key not found at $KEY_FILE"
        exit 1
    fi

    if ! openssl rsa -in "$KEY_FILE" -pubout 2>/dev/null; then
        echo "❌ Failed to extract public key. Check key format and permissions."
        exit 1
    fi
}

create_userkey() {
    local username="$1"
    local force="$2"

    if [ -z "$username" ]; then
        echo "❌ Usage: create_userkey <username> [--force]"
        exit 1
    fi

    local priv_file="$CONFIG_DIR/keys/${username}.private.pem"
    local pub_file="$CONFIG_DIR/keys/${username}.pub.pem"

    # Check for existing keys
    if [ -f "$priv_file" ] || [ -f "$pub_file" ]; then
        if [ "$force" != "--force" ]; then
            echo "⚠️  Key files already exist for user '$username'. Use --force to overwrite."
            exit 1
        else
            echo "⚠️  Overwriting existing keys for '$username'..."
        fi
    fi

    echo "🔐 Generating keypair for user '$username'..."

    # Generate private key
    openssl genpkey -algorithm RSA -out "$priv_file" -pkeyopt rsa_keygen_bits:2048
    chmod 600 "$priv_file"
    do_chown "$priv_file"

    # Extract public key
    openssl rsa -in "$priv_file" -pubout -out "$pub_file"
    chmod 600 "$pub_file"
    do_chown "$pub_file"

    echo "✅ Keypair created:"
    echo "   🔑 Private: $priv_file"
    echo "   📢 Public : $pub_file"
}

export_userkey() {
    local username="$1"

    if [ -z "$username" ]; then
        echo "❌ Usage: export_userkey <username>"
        exit 1
    fi

    local priv_file="$CONFIG_DIR/keys/${username}.private.pem"

    if [ ! -f "$priv_file" ]; then
        echo "❌ No private key found for user '$username' at $priv_file"
        exit 1
    fi

    echo "🔐 Exporting private key for '$username'..."
    cat "$priv_file"
}

install_userkey() {
    local username="$1"
    local arg2="$2"
    local arg3="$3"

    if [ -z "$username" ]; then
        echo "❌ Usage: install_userkey <username> [file] [--overwrite]"
        exit 1
    fi

    # Normalize args
    local source=""
    local flag=""

    if [[ "$arg2" == "--overwrite" ]]; then
        flag="--overwrite"
    elif [[ -n "$arg2" ]]; then
        source="$arg2"
        [[ "$arg3" == "--overwrite" ]] && flag="--overwrite"
    fi

    local dest="$CONFIG_DIR/keys/${username}.pub.pem"
    local priv="$CONFIG_DIR/keys/${username}.private.pem"

    if [ -f "$dest" ] && [ "$flag" != "--overwrite" ]; then
        echo "⚠️  Key already exists for '$username' at $dest. Use --overwrite to replace it."
        exit 1
    fi

    echo "📥 Installing user key for '$username'..."

    # Always delete private key (policy)
    if [ -f "$priv" ]; then
        echo "⚠️  Deleting existing private key: $priv"
        rm -f "$priv"
    fi

    if [ -n "$source" ] && [ -f "$source" ]; then
        echo "📄 Reading key from file: $source"
        cp "$source" "$dest"
    else
        echo "📋 No file provided. Paste the PEM-formatted public key below, then press Ctrl+D:"
        cat > "$dest"
    fi

    if ! grep -q "BEGIN PUBLIC KEY" "$dest"; then
        echo "❌ File does not appear to be a valid PEM public key."
        rm -f "$dest"
        exit 1
    fi

    chmod 600 "$dest"
    do_chown "$dest"

    echo "✅ Installed public key to: $dest"
}

install_ipauth_scripts() {
    echo "🔧 Installing Siglatch ipAuth scripts..."

    # Define base paths
    local src_dir="./scripts"
    local config_src="./default_config/ipAuth"
    local target_base="/etc/siglatch/scripts"
    local config_target="$target_base/ipAuth/config"

    # Copy script directory
    mkdir -p "$target_base"
    cp -r "$src_dir"/* "$target_base/" || {
	echo "❌ Failed to copy scripts"
	return 1
    }

    # Ensure config directory exists
    mkdir -p "$config_target"

    # Copy default config files
    cp "$config_src"/* "$config_target/" || {
	echo "❌ Failed to copy config files"
	return 1
    }

    echo "✅ Scripts and config installed to /etc/siglatch/scripts/ipAuth"
}

echo "🔐 Installing siglatch system configuration..."

if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root." >&2
    exit 1
fi

main() {
    case "$1" in
        repair_key)      do_repair_key ;;
        new_key)         do_new_key ;;
        reinstall)       do_reinstall ;;
	install_ip_auth) install_ipauth_scripts ;;
        install)         do_install ;;
        export_pubkey)   export_pubkey ;;
        create_userkey)  create_userkey "$2" "$3" ;;
        export_userkey)  export_userkey "$2" ;;
        install_userkey) install_userkey "$2" "$3" "$4" ;;
        create_userhmac) create_userhmac "$2" "$3" ;;    # NEW
        export_userhmac) export_userhmac "$2" ;;         # NEW
        help)            show_help ;;
        "")              show_help ;;
        *)               echo "❌ Unknown option: $1"; show_help ;;
    esac
}

main "$@"




echo "✅ siglatch setup complete."
