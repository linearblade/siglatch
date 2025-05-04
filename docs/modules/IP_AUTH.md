# 🔐 Siglatch / ip auth — IP Granting Daemon Module

This module provides secure dynamic IP grant and revoke functionality for `iptables`, with timeouts, logging, and panic flushing built in. It is part of the core Siglatch suite.

---

## 📦 What It Does

* ✅ Grants IPs dynamically using `iptables`
* ⏱️ Auto-expires stale IPs after a configurable TTL
* ❌ Revokes IPs manually
* ☣️ Panic-button flush to wipe all dynamic grants
* 🪀 JSON logs for grants, revokes, and expirations
* 🔌 Cron-friendly, stateless, and audit-focused

---

## 📊 Installation

### Perl Dependencies

Only two non-core Perl modules are required:

```bash
cpanm JSON
cpanm MIME::Base64
```

The rest use core modules:

* `Encode`, `POSIX`, `Time::Piece`, `File::Path`

---

## 📂 Project Layout

| Path                     | Purpose                               |
| ------------------------ | ------------------------------------- |
| `bin/grant.pl`           | Grant an IP (with log + rebuild)      |
| `bin/revoke.pl`          | Revoke an IP (with log + rebuild)     |
| `bin/expire.pl`          | Trigger expiration with audit logging |
| `bin/expire_cron.pl`     | Cron-safe expiration (silent)         |
| `bin/flush.pl`           | Flush all dynamic rules               |
| `lib/Siglatch/Grant.pm`  | Core logic (grant, expire, flush)     |
| `lib/Siglatch/Config.pm` | Shared configuration and constants    |
| `boilerplate.txt`        | Static base firewall rules            |
| `logs/`                  | Runtime logs: `grant_log.json`, etc.  |

---
## Installation
if the installer does not copy the files over , or you wish to reinstall,
you can type ```sh install.sh install_ip_auth``` . This will copy over the scripts into /etc/siglatch/scripts
if you want to setup aliases, follow the instructions at  [CLIENT OPERATIONS](../OPERATIONS_CLIENT.md)
Then you can type things like ```knocker --port 50000 host root grant_ip "message"```

## ⚙️ Configuration

All file paths and operational settings are defined in `lib/Siglatch/Config.pm`. You can update these values to relocate logs or scripts without modifying core logic.

### Default Config Values

```perl
our $logDir         = "$FindBin::Bin/logs";             # Where logs and grant table are stored
our $grantTable     = "$logDir/grants.json";             # JSON index of current granted IPs
our $grantLog       = "$logDir/grant_log.json";          # Human-readable audit log
our $templateFile   = "$FindBin::Bin/boilerplate.txt";  # Static base firewall rules
our $outputScript   = "$FindBin::Bin/lastGrant.sh";      # Final iptables shell script
our $timeoutSeconds = 3600;                               # TTL in seconds for dynamic grants
```

These values are used by all daemon scripts and can be overridden if needed. For example, to store logs in `/var/log/siglatch/`, update `$logDir` and regenerate `grantTable` and `grantLog` paths accordingly.

---

## 🚀 Usage

Find or add these entries to your Siglatch action registry. &#x20;

You can move the scripts anywhere on the system — just update the \`constructor\` path accordingly.

```
# Global action registry
[action:grant_ip]
id = 1
constructor = /usr/bin/perl /root/ipManager/grant.pl
exec_split = 1
keepalive_interval = 300
[action:revoke_ip]
id = 2
constructor = /usr/bin/perl /root/ipManager/revoke.pl
exec_split = 1
keepalive_interval = 300
[action:expire_ips]
id = 3
constructor = /usr/bin/perl /root/ipManager/expire.pl
exec_split = 1
keepalive_interval = 300
[action:flush_ips]
id = 4
constructor = /usr/bin/perl /root/ipManager/flush.pl
exec_split = 1
keepalive_interval = 300
```

Then enable the actions on your server:

```
[server:secure]
enabled = yes
port = 50000
secure = yes
priv_key_path = /etc/siglatch/server_priv.pem
deaddrops = message
actions = grant_ip, revoke_ip,expire_ips, flush_ips
logging = yes
```

Finally, grant them to a particular user:

```
# User access
[user:root]
id = 1
enabled = yes
key_file = /etc/siglatch/keys/root.pub.pem
hmac_file = /etc/siglatch/keys/root.hmac.key
actions = grant_ip,revoke_ip,expire_ips,flush_ips

```

Different users may be given different access levels. &#x20;

For example, \`root\` may have full control, while another user may only be allowed to \`grant\` or \`revoke\`.

### Grant IP Access

```bash
bin/grant.pl <ip> <uid> <username> <action_code> <action_name> <encrypted> <payload_b64>
```

### Revoke IP

```bash
bin/revoke.pl <ip>
```

### Expire (manually with logging)

```bash
bin/expire.pl <ip> <uid> <username> <action_code> <action_name> <encrypted> <payload_b64>
```

### Expire (cron-safe, no user context)

```bash
bin/expire_cron.pl
```

### Flush All Rules (panic button)

```bash
bin/flush.pl <ip> <uid> <username> <action_code> <action_name> <encrypted> <payload_b64>
```

---

## 📡 Triggering Actions

The Siglatch daemon may be triggered by sending an action from a remote client using `knocker`.

### Syntax

```bash
knocker <options> <host> <user_id> <action_id> <payload>
```

### Example: Grant Request by ID

```bash
knocker --port 50000 mydomain.com 1 1 "request access for work on xyz"
```

### Example: Grant Request using Aliases

```bash
knocker --port 50000 mydomain.com root grant_ip "request access"
```

For details on configuring aliases and client authentication, refer to the client operations manual:

📄 `OPERATIONS_CLIENT.md`

---

## 🧾 Example Log Entry

```json
{
  "action": "grant_ip",
  "ip": "192.0.2.123",
  "user": "admin",
  "comment": "b64 decoded payload",
  "b64": 0,
  "timestamp": "2025-05-04T05:48:51Z"
}
```

---

## 🔐 Notes

* All dynamic grants are stored in `logs/grants.json`
* All audit events are written to `logs/grant_log.json`
* `boilerplate.txt` defines the base rule set and is preserved on every change
* Rebuilds `iptables` safely and atomically using `lastGrant.sh`

---

## 📌 Why Use Siglatch?

* Minimal memory footprint
* Secure, stealthy, "off-band" transmission
* No dependencies outside Perl and iptables
* Human-readable, structured audit logs
* Ideal for embedded daemons or headless systems
* Easy to integrate with systemd or shell scripts
