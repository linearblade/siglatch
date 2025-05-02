# Siglatch Client - Operations Manual

**Secure UDP Knock Packet Sender**

The Siglatch client sends encrypted, signed UDP payloads to a listening Siglatch daemon. This document outlines usage, options, alias management, and examples for command-line operations.

---

## 📁 Configuration Directory

Each target host has its own configuration folder:

```
~/.config/siglatch/<host>
```

**Sample structure:**

```
~/.config/siglatch/localhost/
├── action.map         # Action alias map
├── hmac.key           # HMAC key (symmetric)
├── server.pub.pem     # Server public key
├── user.pri.pem       # Client private key (optional)
├── user.pub.pem       # Client public key (optional)
└── user.map           # User alias map
```

⚠️ Hostnames are literal (e.g., `localhost` ≠ `127.0.0.1`).

---

## 🚀 Usage

```bash
program [options] <host> <user-alias-or-id> <action-alias-or-id> <payload>
```

You may also pipe a payload via `--stdin`, or manage aliases separately.

---

## 🔧 Options

| Option                    | Description |
|--------------------------|-------------|
| `--help`                 | Show this help message |
| `--port <num>`           | Override default UDP port (default: `50000`) |
| `--hmac-key <path>`      | Path to HMAC key file |
| `--server-key <path>`    | Path to server public key file |
| `--client-key <path>`    | Path to client private key file |
| `--no-hmac`              | Disable HMAC signing (testing only) |
| `--dummy-hmac`           | Fills HMAC with dummy 0x42 bytes |
| `--stdin`                | Read payload from stdin |
| `--opts-dump`            | Dump parsed option state (debugging) |
| `--no-encrypt`           | Disable payload encryption |
| `--dead-drop`            | Send raw binary payload (no structure) |
| `--verbose <0-5>`        | Verbosity level (default: `3`) |
| `--log <file>`           | Enable logging to specified file |

---

## 🧑‍💼 Alias Commands

### 📥 Add Aliases
```bash
program --alias-user <host> <user> <id>
program --alias-action <host> <action> <id>
```

### 📃 Show Aliases
```bash
program --alias-user-show [host]
program --alias-action-show [host]
program --alias-show <host>
```

### ❌ Delete Individual Aliases
```bash
program --alias-user-delete <host> <user>
program --alias-action-delete <host> <action>
```

### 🔥 Delete Entire Alias Maps
```bash
program --alias-user-delete-map <host> YES
program --alias-action-delete-map <host> YES
program --alias-delete <host> YES
```

---

## 💡 Examples

```bash
# Send knock
program localhost root login "Hello World"

# Send knock with piped input
echo "PING" | program --stdin localhost root ping

# Use alias
program --config-dir ~/.config/siglatch myhost reboot_user reboot_now "Reboot me"

# Create aliases
program --alias-user 127.0.0.1 admin 1
program --alias-action 127.0.0.1 shutdown 99

# View aliases
program --alias-user-show
program --alias-show localhost
```