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
#include "../stdlib/print.h"
#include "../stdlib/unicode.h"
#include "../stdlib/utils.h"
#include "config.h"
#include "nonce_cache.h"

// Global lib object
Lib lib = {
    .log = {0},
    .time = {0},
    .payload = {0},
    .payload_digest = {0},
    .hmac = {0},
    .openssl = {0},
    .net = {0},
    .str = {0},
    .print = {0},
    .unicode = {0}
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
void init_lib(void) {
  //  constructors may not have anything, but we have it if handled for later changes if any, plus we want to libs to all be consistent.
  lib.time = *get_lib_time();
  lib.time.init();
  lib.net             = *get_lib_net();
  lib.net.init();
  lib.str = *get_lib_str();
  lib.str.init();
  lib.unicode = *get_lib_unicode();
  lib.unicode.init();
  lib.print = *get_lib_print();
  PrintContext print_ctx = {
    .unicode = &lib.unicode
  };
  UtilsContext utils_ctx = {
    .print = &lib.print
  };
  lib.print.init(&print_ctx);
  get_lib_utils()->init(&utils_ctx);

  LogContext ctx = {
    .time = &lib.time,
    .print = &lib.print
  };
  lib.log = *get_logger();
  lib.log.init(ctx);

  lib.config = *get_lib_config();
  lib.config.init(NULL);
  lib.nonce = *get_nonce_cache();
  lib.nonce.init();

  lib.payload = *get_payload_lib();
  lib.payload.init();

  lib.payload_digest = *get_payload_digest_lib();
  PayloadDigestContext payload_digest_ctx = {
    .log = &lib.log,
    .openssl = &lib.openssl
  };

  lib.payload_digest.init(&payload_digest_ctx);
  lib.hmac = *get_hmac_key_lib();
  lib.hmac.init();
  lib.file            = *get_lib_file();
  FileLibContext file_ctx = {
    .print             = &lib.print,
    .auto_print_errors = true,
    .allow_unicode     = true
  };
  lib.file.init(&file_ctx);
  lib.openssl         = *get_siglatch_openssl();
  SiglatchOpenSSLContext openssl_ctx = {
        .log   = &lib.log,
        .file  = &lib.file,
        .hmac  = &lib.hmac,
        .print = &lib.print
  };
  lib.openssl.init(&openssl_ctx);
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
  lib.openssl.shutdown();
  lib.hmac.shutdown();
  lib.payload_digest.shutdown();
  lib.payload.shutdown();
  lib.nonce.shutdown();

  lib.config.shutdown();
  lib.log.shutdown();
  get_lib_utils()->shutdown();
  lib.print.shutdown();
  lib.unicode.shutdown();
  lib.time.shutdown();
  lib.net.shutdown();
  lib.str.shutdown();
}
