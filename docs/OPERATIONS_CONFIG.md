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
```

* **log\_file**: Specifies the default path where daemon logs will be written. This setting can be overridden within individual server configurations.

---

## 🔑 Server Definitions

### \[server\:secure]

```ini
enabled = yes
port = 50000
secure = yes
priv_key_path = /etc/siglatch/server_priv.pem
deaddrops = message
actions = grant_ip, run_script
logging = yes
log_file = /custom/log/here
```

* **enabled**: Enables the secure server instance.
* **port**: TCP port to listen on.
* **secure**: Enforces encrypted key validation.
* **priv\_key\_path**: Path to the server's private RSA key.
* **deaddrops**: Comma-separated list of `deaddrop` modules this server responds to.
* **actions**: Comma-separated list of `action` modules available.
* **logging**: Whether to log incoming requests.
* \*\*log\_file\*\*: Overrides the default global log file path for this specific server instance.

### \[server\:insecure]

```ini
enabled = no
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

* All paths should be absolute.
* Scripts will run without the environment. be aware of this when writing scripts.
* User keys should be created via `install.sh` or copied securely.
* HMAC keys must be 32 bytes, hex-safe, and kept secret. or 64 bytes hex as ascii
* Config parsing is strict. Comments must begin with `#`.
* Be sure to reload or restart `siglatchd` after making config changes.
