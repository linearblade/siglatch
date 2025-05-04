$(info -----------------------------------------------------------)
$(info ⚠️  If you get linker errors, run `find_openssl3.sh`)
$(info ⚠️  It will locate OpenSSL installations and suggest flags.)
$(info ⚠️  Then open make file and edit accordingly.)
$(info -----------------------------------------------------------)

.PHONY: all build-knocker build-siglatchd clean clean-knocker clean-siglatchd
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # macOS (Homebrew OpenSSL)
    OPENSSL_CFLAGS = -mmacosx-version-min=12.0 -I/opt/homebrew/opt/openssl@3/include
    OPENSSL_LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib
else
    # Linux default OpenSSL
    OPENSSL_CFLAGS = -I/usr/include
    OPENSSL_LDFLAGS = -L/usr/lib64
endif


# Compiler and flags
CC = gcc
#dev on mac. trouble on my remote. always something.
#CFLAGS = -Wall -O2 -mmacosx-version-min=12.0 \
#  -I/opt/homebrew/opt/openssl@3/include
#LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
CFLAGS += -Wall -O2 $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LDFLAGS) -lssl -lcrypto


# Check if compiler supports C99
C99_CHECK := $(shell \
  echo 'int main(void){int x=1; int y=x+1; return 0;}' | \
  $(CC) -std=c99 -o /dev/null -xc - 2>/dev/null && echo yes || echo no \
)

ifeq ($(C99_CHECK),yes)
  $(info ✅ Compiler supports C99)
else
  $(warning ⚠️  Compiler does NOT support C99)
  $(error ❌ C99 support is required. Please use a compliant compiler or set CC appropriately.)
endif




#CC = gcc
#CFLAGS = -Wall -O2 -I/opt/homebrew/opt/openssl@3/include
#LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
#DEPLOY = MACOSX_DEPLOYMENT_TARGET=12.0

# Output binaries
BIN_SIGLATCHD = siglatchd
BIN_KNOCKER   = knocker

# Source files
#    src/siglatch/config_debug.c \
#    src/siglatch/load_user_keys.c \

SRC_SIGLATCHD = \
    src/siglatch/main.c \
    src/siglatch/config.c \
    src/siglatch/udp_listener.c \
    src/siglatch/decrypt.c \
    src/siglatch/shutdown.c \
    src/siglatch/signal.c \
    src/siglatch/daemon.c \
    src/siglatch/start_opts.c \
    src/siglatch/help.c \
    src/siglatch/lib.c \
    src/siglatch/nonce_cache.c \
    src/siglatch/handle_packet.c \
    src/siglatch/handle_unstructured.c \
    src/stdlib/log.c \
    src/stdlib/hmac_key.c \
    src/stdlib/time.c \
    src/stdlib/net.c \
    src/stdlib/utils.c \
    src/stdlib/payload.c \
    src/stdlib/payload_digest.c \
    src/stdlib/openssl.c \
    src/stdlib/file.c \
    src/stdlib/base64.c

SRC_KNOCKER = \
    src/knock/main.c \
    src/knock/main_helpers.c \
    src/knock/parse_opts.c \
    src/knock/parse_opts_alias.c \
    src/stdlib/parse_argv.c \
    src/knock/print_help.c \
    src/knock/lib.c \
    src/stdlib/log.c \
    src/stdlib/net.c \
    src/stdlib/time.c \
    src/stdlib/utils.c \
    src/stdlib/payload.c \
    src/stdlib/payload_digest.c \
    src/stdlib/random.c \
    src/stdlib/hmac_key.c \
    src/stdlib/file.c \
    src/stdlib/openssl.c \
    src/stdlib/udp.c \
    src/stdlib/utils.c


# Default: build both
all: build-siglatchd build-knocker

# Build siglatchd
build-siglatchd: $(BIN_SIGLATCHD)

$(BIN_SIGLATCHD): $(SRC_SIGLATCHD)
	$(DEPLOY) $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build knocker
build-knocker: $(BIN_KNOCKER)

$(BIN_KNOCKER): $(SRC_KNOCKER)
	$(DEPLOY) $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean targets
clean:
	rm -f $(BIN_SIGLATCHD) $(BIN_KNOCKER)

clean-knocker:
	rm -f $(BIN_KNOCKER)

clean-siglatchd:
	rm -f $(BIN_SIGLATCHD)
