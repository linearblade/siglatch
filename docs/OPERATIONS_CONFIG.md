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

Current note:

* `allowed_ips` is now enforced for `server`, `user`, and `action` scopes.
* `bind_ip` is now honored by startup listener bind.
* `reload_config` now carries bind changes through automatically when the replacement listener can be staged safely.
* Current caveat: same-port `bind_ip` changes still require an explicit `rebind_listener` or a full restart.

---

## 🔑 Server Definitions

### \[server\:secure]

```ini
enabled = yes
label = Secure Server
port = 50000
bind_ip = 127.0.0.1
allowed_ips = 127.0.0.1,192.168.1.0/24
secure = yes
enforce_wire_decode = no
enforce_wire_auth = no
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
* **port**: UDP port to listen on.
* **bind\_ip**: Optional single IPv4 address to bind this listener to. If omitted, the server binds to any local interface. This is honored during startup listener bind and during safe hot reloads.
* **allowed\_ips**: Optional comma-separated list of IPv4 literals and/or IPv4 CIDR ranges allowed to reach this server at all.
  * Examples:
    * `127.0.0.1`
    * `127.0.0.1,192.168.1.0/24`
  * This is enforced at runtime before user/action dispatch.
* **secure**: Enforces encrypted key validation.
* **enforce_wire_decode**: When `yes`, drop packets that fail wire decode or only fall back to unstructured handling. Default: `no`. This is consumed by the mux layer before job dispatch.
* **enforce_wire_auth**: When `yes`, drop structured packets that fail mux-level wire auth instead of passing them onward. Default: `no`. This is consumed by the mux layer before job dispatch.
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
enforce_wire_decode = no
enforce_wire_auth = no
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
enforce_wire_auth = no
payload_overflow = inherit
allowed_ips = 127.0.0.1,10.0.0.0/8
```

* **id**: Numeric action identifier used by clients.
* **enabled**: Enables or disables this action.
* **constructor**: Executable path and optional command prefix.
* **exec\_split**: Whether constructor should be split into command + args before exec.
* **enforce_wire_auth**: When `yes`, require trusted wire auth before daemon-side job handling. Default: `no`. This is app/job policy metadata; the transport layer does not consume it directly.
* **payload\_overflow**: Per-action override for malformed structured payload length handling. Values: `reject`, `clamp`, `inherit`.
* **allowed\_ips**: Optional comma-separated list of IPv4 literals and/or IPv4 CIDR ranges allowed to invoke this action.
  * Examples:
    * `127.0.0.1`
    * `127.0.0.1,10.0.0.0/8`
  * This is enforced at runtime.

---

## 👤 User Access Control

### \[user\:root]

```ini
id = 1
enabled = yes
key_file = /etc/siglatch/keys/root.pub.pem
hmac_file = /etc/siglatch/keys/root.hmac.key
allowed_ips = 127.0.0.1/32
```

* Grants access to the `root` user. root is arbitrary. any name may be used
* Keys must match the server's format and ownership expectations.
* **allowed\_ips**: Optional comma-separated list of IPv4 literals and/or IPv4 CIDR ranges allowed for this user.
  * Examples:
    * `127.0.0.1`
    * `127.0.0.1,192.168.1.0/24`
  * This is enforced at runtime.

---

## ℹ️ Notes

* Runtime output mode precedence is: `--output-mode` CLI flag, then `SIGLATCH_OUTPUT_MODE`, then server `output_mode`, then global `output_mode`, then compile-time default.
* Runtime `payload_overflow` precedence is: action setting, then server setting, then global setting.
* Overflow enforcement applies to structured packet deserialization only.
* With `reject`, malformed structured packets are dropped and never dispatched to action scripts.
* With `clamp`, malformed structured packets are length-clamped and continue through normal structured checks (including signature validation) before dispatch.
* Secure servers reject plaintext receive traffic in the codec / mux path; only encrypted packets are accepted on the structured path.
* Wire enforcement policy is intentionally split from job authorization: server-scoped `enforce_wire_decode` and `enforce_wire_auth` govern mux-level packet handling, while action-scoped `enforce_wire_auth` is enforced in daemon policy after the job has been decoded.
* The `change_setting` builtin currently accepts server-scoped wire policy updates via payload lines such as `server.enforce_wire_decode = yes` and `server.enforce_wire_auth = no`. Action-scoped wire policy is not part of that live-setting path yet.
* The `version` builtin returns the current server banner to the client as a normal action response.
* All paths should be absolute.
* Scripts will run without the environment. be aware of this when writing scripts.
* User keys should be created via `install.sh` or copied securely.
* HMAC keys must be 32 bytes, hex-safe, and kept secret. or 64 bytes hex as ascii
* `bind_ip` must be a single IPv4 literal.
* `allowed_ips` entries must be either single IPv4 literals or IPv4 CIDR expressions.
* IP restriction enforcement order is: `server.allowed_ips`, then `user.allowed_ips`, then `action.allowed_ips`.
* `reload_config` can automatically rebind when the new listener tuple can be staged safely ahead of commit.
* Same-port `bind_ip` changes are intentionally not hot-swapped during `reload_config`; use `rebind_listener` or restart for that case.
* Config parsing is strict. Comments must begin with `#`.
* Wire reject policy keys are parsed from config now; runtime setting propagation and hot-reload handling remain to be wired into the settings flow later.
* Be sure to reload or restart `siglatchd` after making config changes.
