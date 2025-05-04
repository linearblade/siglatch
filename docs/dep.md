# Dependencies

The **siglatch** project requires the following libraries and tools to build and run:

## Required

### OpenSSL 3.x
For cryptographic primitives and secure communication.

**macOS (via Homebrew):**
```bash
brew install openssl@3
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libssl-dev
```

### libc (POSIX-compliant)
Required for standard system and socket functions.

### GNU Make or BSD Make
macOS’s default `make` works; GNU Make preferred:
```bash
brew install make
```

## Optional / Development Tools

### clang-format (code formatting)
```bash
brew install clang-format
```

### lldb (native macOS debugger)
```bash
lldb ./siglatch
```

### Valgrind
For memory checks, not fully supported on macOS.

## Platform Notes

- Tested and developed primarily on **macOS 13+ (Apple Silicon and Intel)**.
- Compatible with **Linux (x86_64)**.
- **Windows is not supported**.


## Compiler Requirements

### C99 Support
The project requires a C compiler that supports the **C99 standard** or later.

**macOS:**
- The default `clang` compiler supports C99. No additional setup is needed.

**Linux:**
- Most distributions include a C99-compatible compiler (`gcc`, `clang`) by default.
- To ensure compatibility, compile with:
```bash
cc -std=c99 ...
```

---
install xxd
(used for hmac dumps, in installation only)
```
yum install vim-common
```