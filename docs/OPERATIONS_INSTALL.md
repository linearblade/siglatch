# 🔐 Siglatch Install Script — Help & Reference Guide

This script sets up and manages cryptographic keys and configuration files for **Siglatch**, a secure daemon for authenticated command execution and HMAC-authenticated user access.

---

## 📦 Overview

* **Location:** `/etc/siglatch`
* **Key file:** `server_priv.pem` (RSA 2048-bit)
* **Config file:** `config` (based on `default_config/config`)
* **User keys:** Stored in `/etc/siglatch/keys/` as `.pem` or `.hmac.key`
* **Permissions:** All key files must be `600` and owned by `root`

---
## 📚 Dependencies

Before installing, ensure your system has the following:

- A **C99-compliant compiler** (`gcc`, `clang`, etc.)
- [`xxd`](https://linux.die.net/man/1/xxd) (typically included with `vim-common`)
- **OpenSSL 3.x or higher** (required for modern crypto support)
- See [`dependencies.md`](./DEPENDENCIES.md) for full details

> 💡 If the **linker fails** during compilation, run the `find_openssl3.sh` script to locate OpenSSL installations and generate appropriate `CFLAGS` and `LDFLAGS` for your `Makefile`.

---

## 🚀 Usage

```bash
sudo ./install.sh <command> [options]
```

> ⚠️ You **must run this script as root**.

---

## 🧰 Commands

### 🛠️ Install & Setup

| Command      | Description                                                                  |
| ------------ | ---------------------------------------------------------------------------- |
| `install`    | One-time install. Creates config and private key. Fails if directory exists. |
| `reinstall`  | Replaces config and regenerates private key.                                 |
| `new_key`    | Generates a new RSA private key.                                             |
| `repair_key` | Fixes permissions and validates an existing key.                             |
| `help`       | Displays this help message.                                                  |

---

### 🔑 Key Management

| Command                                       | Description                                                                          |
| --------------------------------------------- | ------------------------------------------------------------------------------------ |
| `export_pubkey`                               | Outputs the server's public key in PEM format.                                       |
| `create_userkey <user> [--force]`             | Generates an RSA keypair for a user. Overwrites existing keys if `--force` is given. |
| `export_userkey <user>`                       | Outputs a user’s private key.                                                        |
| `install_userkey <user> [file] [--overwrite]` | Installs a user public key from file or prompt. Overwrites if flag is set.           |
| `create_userhmac <user> [--force]`            | Creates a new HMAC (32-byte) key for a user. Use `--force` to overwrite.             |
| `export_userhmac <user>`                      | Outputs a user’s HMAC key as a hex string.                                           |

---

## 🗐 File & Permission Requirements

* Server private key:

  * Must be a valid **RSA private key**.
  * Stored at: `/etc/siglatch/server_priv.pem`
  * **Permissions:** `600`
  * **Owner:** `root:root` (or `root:wheel` on macOS)

* User keys:

  * Public: `${user}.pub.pem`
  * Private: `${user}.private.pem` (deleted on import by policy)
  * HMAC: `${user}.hmac.key`

---

## 🧪 Key Validation Utilities

* The script automatically checks:

  * That the server private key exists and is valid.
  * That the permissions are `600`.
  * That the file is owned by `root` (and `wheel` on macOS).
  * That all PEM-formatted keys contain valid header blocks.

---

## 📝 Configuration Notes

After installing a user key, be sure to **update your config file** with an entry like:

```ini
[user:your_username]
enabled = yes
key_file = /etc/siglatch/keys/your_username.pub.pem
hmac_file = /etc/siglatch/keys/your_username.hmac.key
actions = grant_ip, run_script
```

---

## 🧠 Script Behavior Summary

* Detects OS flavor (Linux vs macOS) for permission handling.
* Creates config and key directories if missing.
* All sensitive files are locked down to `root:root` or `root:wheel`.
* HMACs are 32 bytes, hex-enc
