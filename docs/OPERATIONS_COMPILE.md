# ⚙️ OPERATIONS.md — Operating `siglatch`

## 🏗️ 1. Installation

### Requirements 
* [📦 DEPENDENCIES](./DEPENDENCIES.md) 
- Linux-based operating system (Debian/Ubuntu, RHEL, etc.)
- Root or sufficient user privileges for required scripts (e.g., iptables modifications)
- `gcc`, `make`, and standard build tools (c99)
- OpenSSL 3.0+ libraries (for cryptographic functionality)

### Installation Steps
1. Clone the project repository.
2. Navigate to the base directory.
3. "Deal with openssl"
4. Build binaries using the provided Makefile:

### Installation of OpenSSL 3 & Setting Compiler Flags

If you're unfamiliar with OpenSSL—or on an older system—getting OpenSSL 3 working may require a few extra steps. Luckily, some helpers are provided:

1. Run `find_openssl3.sh` to scan your system for common OpenSSL 3 locations.  
   If it finds them, you're good to go—copy the suggested flags into your Makefile.

2. If not found, check out [📦 DEPENDENCIES](./DEPENDENCIES.md) for detailed installation instructions.  
   On newer systems, it might be as simple as:  
   ```bash  
   sudo yum install openssl-devel
   ```
   Or you can build it from source—the guide covers that too.
   
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
```bash make clean all```

##### Example: Build only the server
```bash make build-siglatchd```

##### Example: Clean builds
```bash make clean```

### Compile-Time Output Mode Defaults

The Makefile supports compile-time output mode defaults:

* `OUTPUT_MODE` applies to both binaries.
* `OUTPUT_MODE_SIGLATCHD` applies only to `siglatchd`.
* `OUTPUT_MODE_KNOCKER` applies only to `knocker`.
* Valid values are `unicode` and `ascii`.

Examples:

```bash
make clean && make OUTPUT_MODE=ascii all
make clean-knocker && make OUTPUT_MODE_KNOCKER=ascii build-knocker
make clean-siglatchd && make OUTPUT_MODE_SIGLATCHD=ascii build-siglatchd
```

Runtime settings can still override compile-time defaults.
For `knocker`, precedence is:

1. `--output-mode`
2. `SIGLATCH_OUTPUT_MODE`
3. `~/.config/siglatch/client.conf` (`output_mode=unicode|ascii`)
4. compile-time default

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
