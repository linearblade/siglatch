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
#include "../stdlib/net.h"
#include "../stdlib/env.h"
#include "../stdlib/file.h"
#include "../stdlib/udp.h"
#include "../stdlib/argv.h"
#include "../stdlib/print.h"
#include "../stdlib/stdin.h"
#include "../stdlib/utils.h"
#include <stdio.h>
// Global lib object
Lib lib = {
    .log = {0},
    .time = {0},
    .random = {0},
    .payload = {0},
    .payload_digest = {0},
    .hmac = {0},
    .env = {0},
    .file = {0},
    .udp = {0},
    .print = {0},
    .stdin = {0},
    .unicode = {0},
    .net = {0}
};

//  SYSTEM INITIALIZATION ORDER 
// ───────────────────────────────────────────────
//  Always initialize in **logical dependency order**
//  This ensures:
//   - Systems are online before others depend on them
//   - Logging is available before any subsystems start
//   - You avoid undefined behavior or silent failures
//
// Example:
//   init_logger();      always first - logs everything
//   init_config();      reads settings needed by others
//   init_network();     connects using config+logs
//
//  This order is the reverse of your shutdown()
// ───────────────────────────────────────────────
int init_lib(void) {
    const UtilsLib *utils = NULL;
    int time_initialized = 0;
    int net_initialized = 0;
    int unicode_initialized = 0;
    int print_initialized = 0;
    int stdin_initialized = 0;
    int log_initialized = 0;
    int random_initialized = 0;
    int payload_initialized = 0;
    int env_initialized = 0;
    int file_initialized = 0;
    int openssl_initialized = 0;
    int hmac_initialized = 0;
    int payload_digest_initialized = 0;
    int udp_initialized = 0;
    int utils_initialized = 0;
    int argv_initialized = 0;

    //  1. Acquire all libraries first (no init yet)
    lib.net             = *get_lib_net();
    lib.time            = *get_lib_time();
    lib.log             = *get_logger();
    lib.random          = *get_random_lib();
    lib.payload         = *get_payload_lib();
    lib.payload_digest  = *get_payload_digest_lib();
    lib.hmac            = *get_hmac_key_lib();
    lib.env             = *get_lib_env();
    lib.file            = *get_lib_file();
    lib.openssl         = *get_siglatch_openssl();
    lib.udp             = *get_udp_lib();
    lib.argv            = *get_lib_argv();
    lib.print           = *get_lib_print();
    lib.stdin           = *get_lib_stdin();
    lib.unicode         = *get_lib_unicode();
    utils               = get_lib_utils();

    if (!utils) {
      fprintf(stderr, "Failed to initialize lib: utils provider unavailable\n");
      return 0;
    }

    /*
     * Wiring contract (intentional): lib factories are all-or-nothing.
     * If required init/shutdown callbacks are present and init_lib() succeeds,
     * the remaining function pointers for those modules are assumed valid per
     * provider contract and are not redundantly guarded at every callsite.
     */
    if (!lib.time.init || !lib.time.shutdown ||
        !lib.net.init || !lib.net.shutdown ||
        !lib.unicode.init || !lib.unicode.shutdown ||
        !lib.print.init || !lib.print.shutdown ||
        !lib.stdin.init || !lib.stdin.shutdown ||
        !lib.log.init || !lib.log.shutdown ||
        !lib.random.init || !lib.random.shutdown ||
        !lib.payload.init || !lib.payload.shutdown ||
        !lib.env.init || !lib.env.shutdown ||
        !lib.file.init || !lib.file.shutdown ||
        !lib.openssl.init || !lib.openssl.shutdown ||
        !lib.hmac.init || !lib.hmac.shutdown ||
        !lib.payload_digest.init || !lib.payload_digest.shutdown ||
        !lib.udp.init || !lib.udp.shutdown ||
        !lib.argv.init || !lib.argv.shutdown ||
        !utils->init || !utils->shutdown) {
      fprintf(stderr, "Failed to initialize lib: incomplete function wiring\n");
      return 0;
    }

    //  2. Build all context structs
    LogContext log_ctx = {
        .time = &lib.time,
        .print = &lib.print
    };

    FileLibContext file_ctx = {
        .print             = &lib.print,
        .auto_print_errors = true,
        .allow_unicode     = true
    };

    SiglatchOpenSSLContext openssl_ctx = {
        .log   = &lib.log,
        .file  = &lib.file,
        .hmac  = &lib.hmac,
        .print = &lib.print
    };
    PayloadDigestContext payload_digest_ctx = {
      .log = &lib.log,
      .openssl = &lib.openssl
    };
    UdpContext udp_ctx = {
      .log = &lib.log,
      .print = &lib.print
    };
    ArgvContext argv_context = {
      .strict = 1
    };
    PrintContext print_ctx = {
      .unicode = &lib.unicode
    };
    StdinContext stdin_ctx = {
      .print = &lib.print
    };
    UtilsContext utils_ctx = {
      .print = &lib.print
    };
    //  3. Initialize all libraries in dependency-safe order
    lib.time.init();             // Time has no dependencies
    time_initialized = 1;
    lib.net.init();
    net_initialized = 1;
    lib.unicode.init();
    unicode_initialized = 1;
    lib.print.init(&print_ctx);
    print_initialized = 1;
    lib.stdin.init(&stdin_ctx);
    stdin_initialized = 1;
    lib.log.init(log_ctx);        // Log depends on time (timestamps)
    log_initialized = 1;
    lib.random.init();            // Random can be independent
    random_initialized = 1;
    lib.payload.init();           // Payload is raw logic (no crypto yet)
    payload_initialized = 1;
    if (!lib.env.init()) {
      fprintf(stderr, "Failed to initialize lib.env\n");
      goto fail;
    }
    env_initialized = 1;
    lib.file.init(&file_ctx);     // FileLib needs options (Unicode etc.)
    file_initialized = 1;
    if (lib.openssl.init(&openssl_ctx) != 0) { // OpenSSL needs log, file, hmac
      fprintf(stderr, "Failed to initialize lib.openssl\n");
      goto fail;
    }
    openssl_initialized = 1;
    lib.hmac.init();              // HMAC key manager (after OpenSSL ready)
    hmac_initialized = 1;
    lib.payload_digest.init(&payload_digest_ctx);
    payload_digest_initialized = 1;
    lib.udp.init(&udp_ctx);
    udp_initialized = 1;
    utils->init(&utils_ctx);
    utils_initialized = 1;
    lib.argv.init(&argv_context);
    argv_initialized = 1;

    return 1;

fail:
    if (argv_initialized) {
      lib.argv.shutdown();
    }
    if (utils_initialized) {
      utils->shutdown();
    }
    if (udp_initialized) {
      lib.udp.shutdown();
    }
    if (payload_digest_initialized) {
      lib.payload_digest.shutdown();
    }
    if (hmac_initialized) {
      lib.hmac.shutdown();
    }
    if (openssl_initialized) {
      lib.openssl.shutdown();
    }
    if (file_initialized) {
      lib.file.shutdown();
    }
    if (env_initialized) {
      lib.env.shutdown();
    }
    if (payload_initialized) {
      lib.payload.shutdown();
    }
    if (random_initialized) {
      lib.random.shutdown();
    }
    if (log_initialized) {
      lib.log.shutdown();
    }
    if (stdin_initialized) {
      lib.stdin.shutdown();
    }
    if (print_initialized) {
      lib.print.shutdown();
    }
    if (unicode_initialized) {
      lib.unicode.shutdown();
    }
    if (net_initialized) {
      lib.net.shutdown();
    }
    if (time_initialized) {
      lib.time.shutdown();
    }

    return 0;
}

//  SYSTEM SHUTDOWN ORDER MATTERS 
// ───────────────────────────────────────────────
//  Always shutdown in **reverse order** of init
//  This ensures:
//   - Dependencies are respected
//   - Essential services (like logging) stay alive
//   - You don't kill your ability to debug on exit
//
// Example:
//   init_logger();
//   init_db();
//   init_network();
//
//   shutdown_network();    no longer needed
//   shutdown_db();         flushed, safe
//   shutdown_logger();     final logs, last to go
//
//  Treat it like a stack: LIFO shutdown!
// ───────────────────────────────────────────────
void shutdown_lib(void) {
  //  clean close
  lib.argv.shutdown();
  get_lib_utils()->shutdown();
  lib.stdin.shutdown();
  lib.print.shutdown();
  lib.unicode.shutdown();
  lib.udp.shutdown();
  lib.openssl.shutdown();
  lib.file.shutdown();
  lib.env.shutdown();
  lib.hmac.shutdown();
  lib.payload_digest.shutdown();
  lib.payload.shutdown();
  lib.random.shutdown();
  lib.log.shutdown();
  lib.net.shutdown();
  lib.time.shutdown();

}
