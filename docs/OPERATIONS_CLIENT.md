# Siglatch Client - Operations Manual

**Secure UDP Knock Packet Sender**

The Siglatch client sends encrypted, signed UDP payloads to a listening Siglatch daemon. This document outlines usage, options, alias management, and examples for command-line operations.

---

## 📁 Configuration Directory

Each target host has its own configuration folder:

```
~/.config/siglatch/<host>
```

Client-wide defaults are stored at:

```
~/.config/siglatch/client.conf
```

**Sample structure:**

```
~/.config/siglatch/localhost/
├── action.map         # Action alias map
├── client.root.conf   # Host+user source-bind defaults (optional)
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
| `--send-from <ipv4>`     | Bind the outbound UDP socket to a specific local IPv4 |
| `--verbose <0-5>`        | Verbosity level (default: `3`) |
| `--log <file>`           | Enable logging to specified file |
| `--output-mode <mode>`   | Output symbols mode: `unicode` or `ascii` |
| `--output-mode-default <mode>` | Persist default output mode to `~/.config/siglatch/client.conf` |

Current note:

* `--send-from` now binds the outbound UDP socket to the requested local IPv4.
* Current caveat: explicit source binding is only supported for IPv4 targets right now.
* A host+user default source bind can be set with `--send-from-default <host> <user> <ipv4>`.

Host+user source binding:

```ini
# ~/.config/siglatch/<host>/client.<user>.conf
send_from_ip = 192.168.1.210
```

Source binding precedence is:

1. `--send-from`
2. `~/.config/siglatch/<host>/client.<user>.conf`
3. no explicit local bind

Manage persisted host+user defaults:

```bash
program --send-from-default <host> <user> <ipv4>
program --send-from-default-clear <host> <user>
```

---

## 🖨️ Output Mode

`knocker` supports two output modes for terminal messages:

* `unicode` (default)
* `ascii`

You can select mode at runtime:

```bash
program --output-mode ascii <host> <user> <action> <payload>
SIGLATCH_OUTPUT_MODE=ascii program <host> <user> <action> <payload>
program --output-mode-default ascii
```

Precedence order is:

1. `--output-mode`
2. `SIGLATCH_OUTPUT_MODE`
3. `~/.config/siglatch/client.conf` (`output_mode=unicode|ascii`)
4. compile-time default from `make`

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
program --alias-show-hosts
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

# Send from a specific local IPv4
program --send-from 127.0.0.1 localhost root login "Hello World"

# Save a host/user default in ~/.config/siglatch/localhost/client.root.conf
program --send-from-default localhost root 192.168.1.210

# then send without repeating --send-from
program localhost root login "Hello World"

# Clear a host/user default
program --send-from-default-clear localhost root

# Create aliases
program --alias-user 127.0.0.1 admin 1
program --alias-action 127.0.0.1 shutdown 99

# View aliases
program --alias-user-show
program --alias-show localhost
program --alias-show-hosts
```
