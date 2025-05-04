✅ Dependencies Checklist

Below is a list of core and optional dependencies required to build and run the siglatch project:

**Required**

* **OpenSSL 3.x** - must have
* **c99 compiler** - newer machines will have this by default.
* **make** - can't compile (pleasantly) without it!
* **xxd** - used for setup and maintenance

**Optional / Development Tools**

* **valgrind/lldb** - not necessary unless you're a hacker and want to test for leaks or other bugs
* **clang-format**
* **eMacs** - b/c it's awesome.

📦 **Installation of OpenSSL 3 and Finding Your Linker / Compiler Flags**

If you're unfamiliar with OpenSSL — especially on an older system — upgrading to OpenSSL 3 may require a few extra steps. Thankfully, helpers have been provided to simplify the process:

🛠️ **Step 1: Detect OpenSSL 3 with find\_openssl3.sh**

Use the provided script to scan your filesystem and detect common OpenSSL 3 install paths:

```bash
./find_openssl3.sh
```

If it outputs paths referencing OpenSSL 3, you're good to go.

Copy the suggested `CPPFLAGS` and `LDFLAGS` into your Makefile or environment.

❗ **Step 2: If OpenSSL 3 Is Not Found**

**macOS (via Homebrew)**

```bash
brew install openssl@3
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

**Linux**

* **Debian / Ubuntu:**

```bash
sudo apt install libssl-dev
```

* **RHEL / CentOS / AlmaLinux:**

```bash
sudo yum install openssl-devel
```

**Building OpenSSL 3 from Source**

If package managers don’t provide OpenSSL 3, you can build it manually:

```bash
wget https://www.openssl.org/source/openssl-3.3.0.tar.gz
# Or check for the latest version at: https://www.openssl.org/source/

tar -xzf openssl-3.3.0.tar.gz
cd openssl-3.3.0
./config --prefix=/usr/local --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

Re-run `find_openssl3.sh` to confirm installation and grab the correct flags.

⚙️ **Other Dependencies**

**libc (POSIX-compliant)**

* Required for standard system and socket functions.

**GNU Make or BSD Make**

* macOS’s default make works, but GNU Make is preferred:

```bash
brew install make
```

**C Compiler (C99 Support Required)**

* **macOS:**

  * macOS ships with clang which supports C99 out of the box.

* **Linux:**

  * Most distros include gcc or clang with C99 support.

To ensure compliance, compile using:

```bash
cc -std=c99 your_source.c
```

🧩 **Installing xxd**

Required for HMAC dumps during installation:

```bash
sudo yum install vim-common
```

Used to dump keys in ASCII format, so you can disseminate them to users. If you want to do it your way, not needed otherwise.

🧰 **Optional Development Tools**

**clang-format**

* For consistent code formatting:

```bash
brew install clang-format
```

**lldb (macOS Debugger)**

```bash
lldb ./siglatch
```

**Valgrind**

* Useful for memory checks, though not fully supported on macOS.

💻 **Platform Notes**

* Developed primarily on macOS 13+ (Apple Silicon and Intel) - for client use
* Linux for server side use
* Compatible with Linux (x86\_64)
* Windows is not yet supported - use WSL :)
