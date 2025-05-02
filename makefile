
.PHONY: all build-knocker build-siglatchd clean clean-knocker clean-siglatchd

# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -mmacosx-version-min=12.0 \
  -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto


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
