$(info -----------------------------------------------------------)
$(info ⚠️  If you get linker errors, run `find_openssl3.sh`)
$(info ⚠️  It will locate OpenSSL installations and suggest flags.)
$(info ⚠️  Then open make file and edit accordingly.)
$(info -----------------------------------------------------------)

# Quick commands:
#   build test objects : make -j4 build-sample-objects
#   clean              : make clean
#   make               : make -j4

.PHONY: all build-knocker build-siglatchd build-sample-objects clean clean-knocker clean-siglatchd
UNAME_S := $(shell uname -s)
OUTPUT_MODE ?= unicode
OUTPUT_MODE_SIGLATCHD ?= $(OUTPUT_MODE)
OUTPUT_MODE_KNOCKER ?= $(OUTPUT_MODE)
CONFIG_PATH_SIGLATCHD ?= /etc/siglatch/server.conf

ifeq ($(UNAME_S),Darwin)
    # macOS (Homebrew OpenSSL)
    OPENSSL_CFLAGS = -mmacosx-version-min=12.0 -I/opt/homebrew/opt/openssl@3/include
    OPENSSL_LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib
    SHARED_EXT = dylib
    SHARED_LDFLAGS = -dynamiclib
else
    # Linux default OpenSSL
    OPENSSL_CFLAGS = -I/usr/include
    OPENSSL_LDFLAGS = -L/usr/lib64
    SHARED_EXT = so
    SHARED_LDFLAGS = -shared
endif


# Compiler and flags
CC = gcc
#dev on mac. trouble on my remote. always something.
#CFLAGS = -Wall -O2 -mmacosx-version-min=12.0 \
#  -I/opt/homebrew/opt/openssl@3/include
#LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
CFLAGS += -Wall -O2 $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LDFLAGS) -lssl -lcrypto

define modeflag_for
$(if $(filter ascii,$(1)),-DSL_OUTPUT_MODE_DEFAULT=SL_OUTPUT_MODE_ASCII,$(if $(filter unicode,$(1)),-DSL_OUTPUT_MODE_DEFAULT=SL_OUTPUT_MODE_UNICODE,-DSL_OUTPUT_MODE_DEFAULT=SL_OUTPUT_MODE_UNICODE))
endef

MODEFLAG_SIGLATCHD := $(call modeflag_for,$(OUTPUT_MODE_SIGLATCHD))
MODEFLAG_KNOCKER   := $(call modeflag_for,$(OUTPUT_MODE_KNOCKER))
CONFIGFLAG_SIGLATCHD := -DSL_CONFIG_PATH_DEFAULT=\"$(CONFIG_PATH_SIGLATCHD)\"

ifneq ($(filter $(OUTPUT_MODE_SIGLATCHD),unicode ascii),$(OUTPUT_MODE_SIGLATCHD))
$(warning ⚠️ Unknown OUTPUT_MODE_SIGLATCHD='$(OUTPUT_MODE_SIGLATCHD)'; defaulting to unicode)
endif
ifneq ($(filter $(OUTPUT_MODE_KNOCKER),unicode ascii),$(OUTPUT_MODE_KNOCKER))
$(warning ⚠️ Unknown OUTPUT_MODE_KNOCKER='$(OUTPUT_MODE_KNOCKER)'; defaulting to unicode)
endif


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
BIN_SAMPLE_DYNAMIC = build/objects/libsample_blurt_dynamic.$(SHARED_EXT)
.PHONY: $(BIN_SIGLATCHD) $(BIN_KNOCKER)

# Source files
#    src/siglatch/config_debug.c \
#    src/siglatch/load_user_keys.c \

SRC_SIGLATCHD = \
    src/siglatch/main.c \
    src/siglatch/app/app.c \
    src/siglatch/app/builtin/builtin.c \
    src/siglatch/app/builtin/bind_target.c \
    src/siglatch/app/builtin/probe_rebind.c \
    src/siglatch/app/builtin/rebind_listener.c \
    src/siglatch/app/builtin/reload_config.c \
    src/siglatch/app/builtin/change_setting.c \
    src/siglatch/app/builtin/save_config.c \
    src/siglatch/app/builtin/load_config.c \
    src/siglatch/app/builtin/list_users.c \
    src/siglatch/app/builtin/test_blurt.c \
    src/siglatch/app/config/config.c \
    src/siglatch/app/config/debug.c \
    src/siglatch/app/daemon4/daemon4.c \
    src/siglatch/app/daemon4/helper.c \
    src/siglatch/app/daemon4/auth.c \
    src/siglatch/app/daemon4/job.c \
    src/siglatch/app/daemon4/request.c \
    src/siglatch/app/daemon4/policy.c \
    src/siglatch/app/daemon4/payload.c \
    src/siglatch/app/daemon4/runner.c \
    src/siglatch/app/daemon4/tick.c \
    src/siglatch/app/help/help.c \
    src/siglatch/app/inbound/inbound.c \
    src/siglatch/app/inbound/crypto/crypto.c \
    src/siglatch/app/keys/keys.c \
    src/siglatch/app/keys/master.c \
    src/siglatch/app/keys/user.c \
    src/siglatch/app/keys/server.c \
    src/siglatch/app/keys/hmac.c \
    src/siglatch/app/object/object.c \
    src/siglatch/app/object/test_static.c \
    src/siglatch/objects/static/sample_blurt.c \
    src/siglatch/app/opts/opts.c \
    src/siglatch/app/payload/codec/codec.c \
    src/siglatch/app/payload/digest/digest.c \
    src/siglatch/app/payload/payload.c \
    src/siglatch/app/payload/reply.c \
    src/siglatch/app/payload/unstructured.c \
    src/siglatch/app/policy/policy.c \
    src/siglatch/app/runtime/runtime.c \
    src/siglatch/app/server/server.c \
    src/siglatch/app/signal/signal.c \
    src/siglatch/app/workspace/workspace.c \
    src/siglatch/app/startup/startup.c \
    src/siglatch/app/udp/udp.c \
    src/siglatch/lifecycle.c \
    src/siglatch/lib.c \
    src/shared/shared.c \
    src/shared/knock/codec/codec.c \
    src/shared/knock/codec3/codec.c \
    src/shared/knock/codec3/context.c \
    src/shared/knock/detect.c \
    src/shared/knock/debug.c \
    src/shared/knock/digest.c \
    src/shared/knock/codec/v1/v1.c \
    src/shared/knock/codec/v2/v2.c \
    src/shared/knock/codec3/v1/v1.c \
    src/shared/knock/codec3/v2/v2.c \
    src/stdlib/log.c \
    src/stdlib/hmac_key.c \
    src/stdlib/nonce.c \
    src/stdlib/signal.c \
    src/stdlib/time.c \
    src/stdlib/net/net.c \
    src/stdlib/net/addr/addr.c \
    src/stdlib/net/ip/ip.c \
    src/stdlib/net/ip/range/range.c \
    src/stdlib/net/socket/socket.c \
    src/stdlib/net/udp/udp.c \
    src/stdlib/protocol/udp/m7mux2/connect/connect.c \
    src/stdlib/protocol/udp/m7mux2/inbox/inbox.c \
    src/stdlib/protocol/udp/m7mux2/outbox/outbox.c \
    src/stdlib/protocol/udp/m7mux2/ingress/ingress.c \
    src/stdlib/protocol/udp/m7mux2/normalize/adapter/adapter.c \
    src/stdlib/protocol/udp/m7mux2/normalize/normalize.c \
    src/stdlib/protocol/udp/m7mux2/session/session.c \
    src/stdlib/protocol/udp/m7mux2/stream/stream.c \
    src/stdlib/protocol/udp/m7mux2/egress/egress.c \
    src/stdlib/protocol/udp/m7mux2/m7mux2.c \
    src/stdlib/process/process.c \
    src/stdlib/process/user/user.c \
    src/stdlib/utils.c \
    src/stdlib/openssl.c \
    src/stdlib/print.c \
    src/stdlib/unicode.c \
    src/stdlib/file.c \
    src/stdlib/argv.c \
    src/stdlib/parse/ini.c \
    src/stdlib/parse/parse.c \
    src/stdlib/str.c \
    src/stdlib/base64.c

SRC_KNOCKER = \
    src/knock/main.c \
    src/knock/app/app.c \
    src/knock/app/opts/opts.c \
    src/knock/app/env/env.c \
    src/knock/app/alias/alias.c \
    src/knock/app/alias/command.c \
    src/knock/app/alias/ops.c \
    src/knock/app/help/help.c \
    src/knock/app/error/argv.c \
    src/knock/app/opts/alias.c \
    src/knock/app/opts/transmit.c \
    src/knock/app/output_mode/output_mode.c \
    src/knock/app/transmit/transmit.c \
    src/knock/app/transmit/helper.c \
    src/shared/shared.c \
    src/shared/knock/codec/codec.c \
    src/shared/knock/codec3/codec.c \
    src/shared/knock/codec3/context.c \
    src/shared/knock/detect.c \
    src/shared/knock/debug.c \
    src/shared/knock/digest.c \
    src/shared/knock/codec/v1/v1.c \
    src/shared/knock/codec/v2/v2.c \
    src/shared/knock/codec3/v1/v1.c \
    src/shared/knock/codec3/v2/v2.c \
    src/stdlib/argv.c \
    src/stdlib/parse/ini.c \
    src/stdlib/parse/parse.c \
    src/stdlib/str.c \
    src/knock/lib.c \
    src/stdlib/log.c \
    src/stdlib/net/net.c \
    src/stdlib/net/addr/addr.c \
    src/stdlib/net/ip/ip.c \
    src/stdlib/net/ip/range/range.c \
    src/stdlib/net/socket/socket.c \
    src/stdlib/net/udp/udp.c \
    src/stdlib/protocol/udp/m7mux2/connect/connect.c \
    src/stdlib/protocol/udp/m7mux2/inbox/inbox.c \
    src/stdlib/protocol/udp/m7mux2/outbox/outbox.c \
    src/stdlib/protocol/udp/m7mux2/ingress/ingress.c \
    src/stdlib/protocol/udp/m7mux2/normalize/adapter/adapter.c \
    src/stdlib/protocol/udp/m7mux2/normalize/normalize.c \
    src/stdlib/protocol/udp/m7mux2/session/session.c \
    src/stdlib/protocol/udp/m7mux2/stream/stream.c \
    src/stdlib/protocol/udp/m7mux2/egress/egress.c \
    src/stdlib/protocol/udp/m7mux2/m7mux2.c \
    src/stdlib/nonce.c \
    src/stdlib/signal.c \
    src/stdlib/time.c \
    src/stdlib/utils.c \
    src/stdlib/random.c \
    src/stdlib/env.c \
    src/stdlib/stdin.c \
    src/stdlib/hmac_key.c \
    src/stdlib/file.c \
    src/stdlib/openssl.c \
    src/stdlib/print.c \
    src/stdlib/unicode.c \
    src/stdlib/utils.c


# Default: build both
all: build-siglatchd build-knocker

# Build siglatchd
build-siglatchd: $(BIN_SIGLATCHD)

$(BIN_SIGLATCHD): $(SRC_SIGLATCHD)
	$(DEPLOY) $(CC) $(CFLAGS) $(MODEFLAG_SIGLATCHD) $(CONFIGFLAG_SIGLATCHD) -o $@ $^ $(LDFLAGS)

# Build knocker
build-knocker: $(BIN_KNOCKER)

$(BIN_KNOCKER): $(SRC_KNOCKER)
	$(DEPLOY) $(CC) $(CFLAGS) $(MODEFLAG_KNOCKER) -o $@ $^ $(LDFLAGS)

# Build sample dynamic objects
build-sample-objects: $(BIN_SAMPLE_DYNAMIC)

$(BIN_SAMPLE_DYNAMIC): src/siglatch/objects/dynamic/sample_blurt.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I. $(SHARED_LDFLAGS) -o $@ $<

# Clean targets
clean:
	rm -f $(BIN_SIGLATCHD) $(BIN_KNOCKER) $(BIN_SAMPLE_DYNAMIC)

clean-knocker:
	rm -f $(BIN_KNOCKER)

clean-siglatchd:
	rm -f $(BIN_SIGLATCHD)
