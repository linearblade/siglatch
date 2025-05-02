# ⚙️ OPERATIONS.md — Operating `siglatch`

## 🏗️ 1. Installation

### Requirements
- Linux-based operating system (Debian/Ubuntu, RHEL, etc.)
- Root or sufficient user privileges for required scripts (e.g., iptables modifications)
- `gcc`, `make`, and standard build tools
- OpenSSL libraries (for cryptographic functionality)

### Installation Steps
1. Clone the project repository.
2. Navigate to the base directory.
3. Build binaries using the provided Makefile:

#### Building From Source
The Makefile provides the following build options:

| Target | Description |
|:---|:---|
| `make` | Default: builds both `siglatchd` and `knocker`. |
| `make build-siglatchd` | Build only the server daemon (`siglatchd`). |
| `make build-knocker` | Build only the client knock tool (`knocker`). |
| `make clean` | Remove all compiled binaries. |
| `make clean-siglatchd` | Remove only the `siglatchd` binary. |
| `make clean-knocker` | Remove only the `knocker` binary. |

##### Example: Full build
```bash
make
```

##### Example: Build only the server
```bash
make build-siglatchd
```

##### Example: Clean builds
```bash
make clean
```

4. Review the `default_config/` directory. Example configurations and sample user settings are provided.
5. Run the installation script as root:

```bash
sudo ./install.sh
```

- `install.sh` will present a menu of installation options.
- Current default installation path for `siglatchd` configuration is `/etc/siglatch/`.
- Future updates may allow a configurable installation target.

6. After installing the base system, edit the configuration to add users individually.

---

## ⚡ Quick Start for Local Testing

A default script is included (which simply echoes text for testing purposes).

To quickly test that everything is working:
1. Review the Configuration File, Set up a key, using the install.sh script.
1. Start the daemon:
```bash
./siglatchd
```

2. In another terminal, send a test packet with the client:
* [⚙️ CLIENT\_OPERATIONS.md](CLIENT_OPERATIONS.md) — How to install, configure, run, and maintain siglatch client.
```bash
./knocker localhost 1 1 --dead-drop "i am a test"
./knocker localhost 1 1 "i am a test"
./knocker localhost 1 1 --no-encrypt --dead-drop "i am a test"
./knocker localhost 1 1 --no-encrypt --dead-drop "i am a test"

```

- This will send a packet to your localhost (127.0.0.1).
- You should see output in the log file or console showing that the script was executed (printing the test message).
- This confirms that the knock-send-receive-execute cycle is working properly.

---

## 🛠️ 2. Configuration

### Core Settings
- **Actions**: Define available scriptable actions in the configuration.
- **Users**: Assign users a subset of the available actions.
- **Scripts**: Configure which scripts are run for each action (e.g., IP grant, IP revoke).
- **Timeouts**: Define keepalive timeouts for session expiration.

### Managing Users
- After installation, users must be added manually.
- A sample user configuration is provided in the `default_config/` directory.
- For each user:
  - Add a user entry in the configuration.
  - Install a **server RSA key**.
  - Install a **user RSA key**.
  - Install a **user HMAC key**.
- Keys must be correctly referenced in the configuration file.

### Managing User Keys
- **Option 1**: Generate RSA keys on the server via the installation interface.
  - Public keys can be exported and sent to users securely.
- **Option 2**: Accept a provided public RSA key from the user.
  - Install the user's public key via the management interface.

Rotation and key management processes should always be performed carefully.

---

## 🚀 3. Starting and Managing Services

### Starting `siglatchd`
```bash
./siglatchd [--dump-config] [--help]
```

#### Options:
- `--dump-config` : Print parsed configuration and exit.
- `--help` : Show this help message.


- At present, `siglatchd` expects a configuration located at `/etc/siglatch/`.
- **Important**: This behavior is expected to change rapidly. By the time you read this document, it is likely that you can specify the configuration directory explicitly:

```bash
./siglatchd -c /path/to/config/
```

- If no `-c` option is provided, it will continue to attempt loading from the default path.

### Stopping `siglatchd`
- Gracefully terminate the process with `SIGINT` or `SIGTERM`.
- Always verify clean shutdown by inspecting logs.

---

## 🔍 4. Monitoring and Logs

- **Log location**: Configurable; defaults to system log or project directory.
- **Types of logs**:
  - Packet validation failures
  - Successful grants/revokes
  - Replay attack attempts
  - Signature validation errors

### Logging Modes
- **Standard Mode**: Logs all relevant activities for security and diagnostics.
- **Super Spy Mode**: Logging can be disabled entirely for stealth operations.
- **Debug/Testing Mode**: Logs can be redirected to the terminal for live monitoring during testing or debugging.

> You can either **log and monitor** activity, **disable logging**, or **watch live output** depending on mission needs.

Monitor logs actively if operating in monitored or high-risk environments.

---

## 🚨 5. Emergency Operations

Currently, no kill switch is implemented. However, the following emergency system operations are planned to be configurable (and can be disabled if desired):

- **Sleep**: Temporarily disable operations until a defined event or time.
- **Shutdown**: Remotely terminate the daemon cleanly.
- **Reload**: Reload the configuration remotely without full shutdown.
- **Force Timeouts**: Immediately timeout active scripts and trigger their associated destructor scripts.
- **Enable/Disable Actions**: Remotely turn specific actions on or off dynamically.

---

## ⚙️ 6. Maintenance

- **Key Rotation**: Periodically regenerate server or client keys for enhanced security.
- **Backup Procedures**: Regularly back up:
  - Config files
  - User ACLs
  - Management scripts
- **Configuration Updates**:
  - Can be staged and applied with minimal downtime if planned.

---

## 🤖 7. Client Operations

### Using `knocker`

To send a request from the client side:
```bash
./knocker <host> <user> <action> <payload>
```

- Keys are stored and retrieved based on the `host` and `user` combination.
- If you provide an IP address, it will match the IP directly.
- If you provide a domain name, it will match the domain string exactly.
- **Important**: It will **not** automatically resolve domains (e.g., `www.domain.com` vs `domain.com` must be managed manually by the user).

### Client Behavior
- **One packet only**: The client presently sends exactly **one packet** per request.
- **Payload size**: Limited to **199 bytes** total. Plan your payloads wisely!

### Planned Client Enhancements
- Interactive configuration mode to select targets, users, and actions more easily.
- Support for splitting larger payloads across multiple packets.
  - Receiving server-side scripts will be responsible for reassembling larger data streams before execution.

---

## ⚠️ 8. Known Risks and Limitations

- Heavy UDP floods can cause log bloating (monitor log file sizes).
- Time synchronization issues between client and server can cause packet rejections.
- No built-in IP banning or automatic rate-limiting (planned feature).
- External scripts must be safe: running arbitrary scripts without review is dangerous.

---

# ✅ Quick Summary
- **Install carefully**, **configure cautiously**, **script responsibly**.
- `siglatchd` is hardened but assumes a trusted operational environment.
- Monitor logs and react quickly to signs of replay attempts or resource exhaustion.

---

*This operational guide will evolve as features like server-to-client communication and automated IP banning are implemented.*

