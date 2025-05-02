
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
    - `make` - builds both `siglatchd` and `knocker`
    - `make build-siglatchd` - build only the server daemon
    - `make build-knocker` - build only the client
    - `make clean` - remove all compiled binaries
4. Review the `default_config/` directory. Example configurations and sample user settings are provided.
5. Run the installation script as root:
```bash
sudo ./install.sh
```
- Current default installation path for configuration: `/etc/siglatch/`.
- Future: configurable installation target.
6. After installing, edit the config to add users individually.

---

## ⚡ Quick Start for Local Testing
- Start daemon:
```bash
./siglatchd
```
- In another terminal, send a test packet:
```bash
./knocker "i am a test"
```
- Observe logs or terminal output for script execution.

---

## 🛠️ 2. Configuration

- Define scriptable actions.
- Assign user permissions.
- Configure timeout durations.
- Manage script paths.
- User keys must be installed (server key, user key, HMAC key).

---

## 🚀 3. Starting and Managing Services

- Start daemon:
```bash
./siglatchd [--dump-config] [--help]
```
Options:
- `--dump-config` - Print parsed configuration and exit.
- `--help` - Show help message.
- Config expected at `/etc/siglatch/`, override with `-c /path/to/config/`.

- Stop daemon safely with `SIGINT` or `SIGTERM`.

---

## 🔍 4. Monitoring and Logs

- Logging options:
    - **Standard Mode**: Log activities.
    - **Super Spy Mode**: Disable logging.
    - **Debug Mode**: Output logs to terminal.

---

## 🚨 5. Emergency Operations

(No kill switch yet. Planned operations:)

- **Sleep**: Temporarily disable operations.
- **Shutdown**: Remotely terminate daemon.
- **Reload**: Reload configuration remotely.
- **Force Timeout**: Timeout active scripts.
- **Enable/Disable Actions**: Dynamically control actions.

---

## ⚙️ 6. Maintenance

- Rotate keys periodically.
- Backup configs, user ACLs, scripts.
- Update configuration safely with minimal downtime.

---

## 🤖 7. Client Operations

Usage:
```bash
./knocker <host> <user> <action> <payload>
```
- Host/user matched exactly.
- 199-byte payload limit.
- One packet per request.

Future:
- Interactive client mode.
- Larger payload support (manual reassembly by scripts).

---

## ⚠️ 8. Known Risks and Limitations

- Risk of log bloating during UDP floods.
- Risk of time drift issues.
- External scripts must be trusted.

---

# ✅ Quick Summary
- Install carefully.
- Configure cautiously.
- Script responsibly.
- Monitor and respond actively.

---

*This operational guide will evolve alongside future siglatch features.*
