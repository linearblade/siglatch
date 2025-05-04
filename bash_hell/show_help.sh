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
  create_userkey <user> Generate a new keypair for a user
  export_userkey <user> Output a user's private key (e.g. for email)
  install_userkey <user> [file] [--overwrite]
                        Install a user public key from file or prompt

Notes:
- This script must be run as root.
- Config will be created in /etc/siglatch/
- Keys are stored in /etc/siglatch/keys/
- All PEM files must be mode 600 and root-owned

EOF
    exit 0
}
