/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "lib.h"
#include "../stdlib/log.h"
#include "../stdlib/time.h"
#include "../stdlib/log_context.h"
#include "../stdlib/payload.h"
#include "../stdlib/payload_digest.h"
#include "../stdlib/random.h"
#include "../stdlib/hmac_key.h"
#include "../stdlib/file.h"
#include "../stdlib/udp.h"
#include "../stdlib/parse_argv.h"
// Global lib object
Lib lib = {
    .log = {0},
    .time = {0},
    .random = {0},
    .payload = {0},
    .payload_digest = {0},
    .hmac = {0},
    .file = {0},
    .udp = {0}
};

// 🚀 SYSTEM INITIALIZATION ORDER 🚀
// ───────────────────────────────────────────────
// 🟢 Always initialize in **logical dependency order**
// 🧩 This ensures:
//   - Systems are online before others depend on them
//   - Logging is available before any subsystems start
//   - You avoid undefined behavior or silent failures
//
// Example:
//   init_logger();     ✅ always first — logs everything
//   init_config();     ✅ reads settings needed by others
//   init_network();    ✅ connects using config+logs
//
// 🔁 This order is the reverse of your shutdown()
// ───────────────────────────────────────────────
void init_lib(void) {
    // 🎯 1. Acquire all libraries first (no init yet)
    lib.time            = *get_lib_time();
    lib.log             = *get_logger();
    lib.random          = *get_random_lib();
    lib.payload         = *get_payload_lib();
    lib.payload_digest  = *get_payload_digest_lib();
    lib.hmac            = *get_hmac_key_lib();
    lib.file            = *get_lib_file();
    lib.openssl         = *get_siglatch_openssl();
    lib.udp             = *get_udp_lib();
    lib.parse_argv      = *get_lib_parse_argv();
    // 🎯 2. Build all context structs
    LogContext log_ctx = {
        .time = &lib.time
    };

    FileLibContext file_ctx = {
        .auto_print_errors = true,
        .allow_unicode     = true
    };

    SiglatchOpenSSLContext openssl_ctx = {
        .log   = &lib.log,
        .file  = &lib.file,
        .hmac  = &lib.hmac
    };
    PayloadDigestContext payload_digest_ctx = {
      .log = &lib.log,
      .openssl = &lib.openssl
    };
    UdpContext udp_ctx = {
      .log = &lib.log
    };
    ParseArgvContext parse_argv_context = {
      .strict = 1,
      .log = &lib.log
    }; 
    // 🎯 3. Initialize all libraries in dependency-safe order
    lib.time.init();             // Time has no dependencies
    lib.log.init(log_ctx);        // Log depends on time (timestamps)
    lib.random.init();            // Random can be independent
    lib.payload.init();           // Payload is raw logic (no crypto yet)
    lib.file.init(&file_ctx);     // FileLib needs options (Unicode etc.)
    lib.openssl.init(&openssl_ctx); // OpenSSL needs log, file, hmac
    lib.hmac.init();              // HMAC key manager (after OpenSSL ready)
    lib.payload_digest.init(&payload_digest_ctx);
    lib.udp.init(&udp_ctx);
    lib.parse_argv.init(&parse_argv_context);
}

// 🚨 SYSTEM SHUTDOWN ORDER MATTERS 🚨
// ───────────────────────────────────────────────
// 🔻 Always shutdown in **reverse order** of init
// 🔁 This ensures:
//   - Dependencies are respected
//   - Essential services (like logging) stay alive
//   - You don’t kill your ability to debug on exit
//
// Example:
//   init_logger();
//   init_db();
//   init_network();
//
//   shutdown_network();   ✅ no longer needed
//   shutdown_db();        ✅ flushed, safe
//   shutdown_logger();    ✅ final logs, last to go
//
// 🧠 Treat it like a stack: LIFO shutdown!
// ───────────────────────────────────────────────
void shutdown_lib(void) {
  // 🔻 clean close
  lib.parse_argv.shutdown();
  lib.udp.shutdown();
  lib.openssl.shutdown();
  lib.file.shutdown();
  lib.hmac.shutdown();
  lib.payload_digest.shutdown();
  lib.payload.shutdown();
  lib.random.shutdown();
  lib.log.shutdown();
  lib.time.shutdown();

}
