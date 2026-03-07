# 📊 Siglatch Daemon Configuration Manual

This manual describes how to configure `siglatchd`, the secure access daemon for handling remote actions using authenticated keys, HMACs, and programmable action routing.

Keep in mind the following:&#x20;

* even if you run unencrypted, siglatch will still require key information. This will be fixed in later revisions.
* Only 1 server may be run in this version. expect a new version to be released shortly. if you wish to change the server running, open up siglatchd and rewrite the server ’secure’ ```lib.config.set_current_server(’secure’);```
* insecure mode DOES work. you can simply change the secure key to no or 0. 
* dead drops are meant as a catch all , or requesting onboarding. actions are more appropriate for typical usage.
* destructors do not work yet. There is no design hindrance. just a time hindrance. will be revised shortly

---

## 💾 Global Settings

```ini
log_file = /tmp/siglatch.log
output_mode = unicode
payload_overflow = reject
```

* **log\_file**: Specifies the default path where daemon logs will be written. This setting can be overridden within individual server configurations.
* **output\_mode**: Default console output mode for daemon messages. Valid values: `unicode`, `ascii`.
* **payload\_overflow**: Default policy for malformed structured packets whose `payload_len` exceeds the packet payload buffer.
  * Global values: `reject`, `clamp`
  * `reject`: Drop packet immediately.
  * `clamp`: Force `payload_len` to the payload buffer size and continue structured validation/dispatch flow.

---

## 🔑 Server Definitions

### \[server\:secure]

```ini
enabled = yes
label = Secure Server
port = 50000
secure = yes
output_mode = unicode
payload_overflow = inherit
priv_key_path = /etc/siglatch/server_priv.pem
deaddrops = message
actions = grant_ip, run_script
logging = yes
log_file = /custom/log/here
```

* **enabled**: Enables the secure server instance.
* **label**: Optional human-readable display label. This does not affect server selection.
* **port**: TCP port to listen on.
* **secure**: Enforces encrypted key validation.
* **priv\_key\_path**: Path to the server's private RSA key.
* **deaddrops**: Comma-separated list of `deaddrop` modules this server responds to.
* **actions**: Comma-separated list of `action` modules available.
* **logging**: Whether to log incoming requests.
* \*\*log\_file\*\*: Overrides the default global log file path for this specific server instance.
* **output\_mode**: Overrides global `output_mode` for this server.
* **payload\_overflow**: Overrides global `payload_overflow` for this server. Values: `reject`, `clamp`, `inherit`.
* **server identity**: The section header `[server:<name>]` is the machine identifier used by `--server`, `SIGLATCH_SERVER`, and `default_server`.
* **deprecated alias**: `name = ...` maps to `label` only; it no longer renames the server identifier.

### \[server\:insecure]

```ini
enabled = no
label = Insecure Server
port = 50001
deaddrops = pubkey
secure = no
```

* Same options as above, but without key validation. Disabled by default.

---

## 🚫 Deaddrop Definitions

### \[deaddrop\:message]

```ini
constructor = /bin/sh path/to/script/here
destructor  = /bin/teardown/path (unimplemented)
keepalive_interval   = timer until teardown (unimplemented)
require_ascii = yes
starts_with = message
exec_split = yes
```

* **constructor**: Executable script for handling message input.
* \*\*destructor\*\*: This script fires after keepalive seconds have passed with same inputs
* **require\_ascii**: Reject binary or non-ASCII payloads.
* **starts\_with**: Trigger keyword to associate input with this deaddrop.
* **exec\_split**: Whether to split arguments during execution. by default most scripts will run fine, set to 0 or no if you have a script with spaces in it.

###

---

## ⚙️ Action Definitions

### \[action\:grant\_ip]

```ini
id = 1
enabled = yes
constructor = /usr/bin/perl /etc/siglatch/scripts/ipAuth/grant.pl
exec_split = yes
payload_overflow = inherit
```

* **id**: Numeric action identifier used by clients.
* **enabled**: Enables or disables this action.
* **constructor**: Executable path and optional command prefix.
* **exec\_split**: Whether constructor should be split into command + args before exec.
* **payload\_overflow**: Per-action override for malformed structured payload length handling. Values: `reject`, `clamp`, `inherit`.

---

## 👤 User Access Control

### \[user\:root]

```ini
id = 1
enabled = yes
key_file = /etc/siglatch/keys/root.pub.pem
hmac_file = /etc/siglatch/keys/root.hmac.key
```

* Grants access to the `root` user. root is arbitrary. any name may be used
* Keys must match the server's format and ownership expectations.

---

## ℹ️ Notes

* Runtime output mode precedence is: `--output-mode` CLI flag, then `SIGLATCH_OUTPUT_MODE`, then server `output_mode`, then global `output_mode`, then compile-time default.
* Runtime `payload_overflow` precedence is: action setting, then server setting, then global setting.
* Overflow enforcement applies to structured packet deserialization only.
* With `reject`, malformed structured packets are dropped and never dispatched to action scripts.
* With `clamp`, malformed structured packets are length-clamped and continue through normal structured checks (including signature validation) before dispatch.
* All paths should be absolute.
* Scripts will run without the environment. be aware of this when writing scripts.
* User keys should be created via `install.sh` or copied securely.
* HMAC keys must be 32 bytes, hex-safe, and kept secret. or 64 bytes hex as ascii
* Config parsing is strict. Comments must begin with `#`.
* Be sure to reload or restart `siglatchd` after making config changes.
