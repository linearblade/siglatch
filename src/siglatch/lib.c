/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "lib.h"
#include "../stdlib/log.h"
#include "../stdlib/time.h"
#include "../stdlib/log_context.h"
#include "../stdlib/argv.h"
#include "../stdlib/nonce.h"
#include "../stdlib/signal.h"
#include "../stdlib/parse/parse.h"
#include "../stdlib/process/process.h"
#include "../stdlib/print.h"
#include "../stdlib/protocol/udp/m7mux/m7mux.h"
#include "../stdlib/unicode.h"
#include "../stdlib/utils.h"

// Global lib object
Lib lib = {
    .log = {0},
    .time = {0},
    .hmac = {0},
    .openssl = {0},
    .nonce = {0},
    .signal = {0},
    .net = {0},
    .m7mux = {0},
    .process = {0},
    .str = {0},
    .parse = {0},
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
int init_lib(void) {
  const UtilsLib *utils = NULL;
  const SharedKnockCodecContextLib *codec_context_lib = NULL;
  int time_initialized = 0;
  int net_initialized = 0;
  int codec_context_initialized = 0;
  int str_initialized = 0;
  int process_initialized = 0;
  int argv_initialized = 0;
  int parse_initialized = 0;
  int unicode_initialized = 0;
  int print_initialized = 0;
  int utils_initialized = 0;
  int log_initialized = 0;
  int hmac_initialized = 0;
  int nonce_initialized = 0;
  int signal_initialized = 0;
  int file_initialized = 0;
  int openssl_initialized = 0;
    int m7mux_initialized = 0;

  // constructors first so init order and failure handling stay centralized
  lib.time = *get_lib_time();
  lib.net = *get_lib_net();
  lib.process = *get_lib_process();
  lib.str = *get_lib_str();
  lib.argv = *get_lib_argv();
  lib.parse = *get_lib_parse();
  lib.unicode = *get_lib_unicode();
  lib.print = *get_lib_print();
  lib.log = *get_logger();
  lib.hmac = *get_hmac_key_lib();
  lib.file = *get_lib_file();
  lib.nonce = *get_lib_nonce();
  lib.signal = *get_lib_signal();
  lib.openssl = *get_siglatch_openssl();
  lib.m7mux = *get_lib_m7mux();
  utils = get_lib_utils();
  codec_context_lib = get_shared_knock_codec_context_lib();

  if (!utils) {
    fprintf(stderr, "Failed to initialize siglatchd lib runtime: utils provider unavailable\n");
    return 0;
  }

  if (!codec_context_lib || !codec_context_lib->init || !codec_context_lib->shutdown ||
      !codec_context_lib->create || !codec_context_lib->destroy ||
      !codec_context_lib->set_server_key || !codec_context_lib->clear_server_key ||
      !codec_context_lib->add_keychain || !codec_context_lib->remove_keychain) {
    fprintf(stderr, "Failed to initialize siglatchd lib runtime: codec context provider unavailable\n");
    return 0;
  }

  if (!lib.time.init || !lib.time.shutdown ||
      !lib.time.monotonic_ms ||
      !lib.net.init || !lib.net.shutdown ||
      !lib.m7mux.connect.init || !lib.m7mux.connect.set_context || !lib.m7mux.connect.shutdown ||
      !lib.m7mux.connect.state_init || !lib.m7mux.connect.state_reset ||
      !lib.m7mux.connect.connect_ip || !lib.m7mux.connect.connect_socket ||
      !lib.m7mux.connect.disconnect ||
      !lib.m7mux.init || !lib.m7mux.shutdown || !lib.m7mux.set_context ||
      !lib.process.init || !lib.process.shutdown ||
      !lib.str.init || !lib.str.shutdown ||
      !lib.argv.init || !lib.argv.shutdown ||
      !lib.parse.init || !lib.parse.shutdown ||
      !lib.unicode.init || !lib.unicode.shutdown ||
      !lib.print.init || !lib.print.shutdown ||
      !lib.log.init || !lib.log.shutdown ||
      !lib.hmac.init || !lib.hmac.shutdown ||
      !lib.file.init || !lib.file.shutdown ||
      !lib.nonce.init || !lib.nonce.shutdown ||
      !lib.nonce.cache_init || !lib.nonce.cache_shutdown ||
      !lib.nonce.clear || !lib.nonce.check || !lib.nonce.add ||
      !lib.signal.init || !lib.signal.shutdown ||
      !lib.signal.state_reset || !lib.signal.install || !lib.signal.uninstall ||
      !lib.signal.should_exit || !lib.signal.last_signal ||
      !lib.signal.take_last_signal || !lib.signal.has_pending ||
      !lib.signal.clear_pending || !lib.signal.request_exit ||
      !lib.openssl.init || !lib.openssl.shutdown ||
      !utils->init || !utils->shutdown) {
    fprintf(stderr, "Failed to initialize siglatchd lib runtime: incomplete function wiring\n");
    return 0;
  }

  lib.time.init();
  time_initialized = 1;

  lib.net.init();
  net_initialized = 1;

  if (!codec_context_lib->init()) {
    fprintf(stderr, "Failed to initialize siglatchd codec context provider\n");
    goto fail;
  }
  codec_context_initialized = 1;

  {
    M7MuxContext m7mux_ctx = {
      .socket = &lib.net.socket,
      .udp = &lib.net.udp,
      .time = &lib.time,
      .codec_context = NULL,
      .reserved = NULL
    };

    if (!lib.m7mux.init(&m7mux_ctx)) {
      fprintf(stderr, "Failed to initialize siglatchd lib.m7mux\n");
      goto fail;
    }
  }
  m7mux_initialized = 1;

  if (!lib.process.init()) {
    fprintf(stderr, "Failed to initialize siglatchd lib.process\n");
    goto fail;
  }
  process_initialized = 1;

  lib.str.init();
  str_initialized = 1;

  {
    ArgvContext argv_ctx = {
      .strict = 1
    };
    lib.argv.init(&argv_ctx);
  }
  argv_initialized = 1;

  {
    ParseContext parse_ctx = {
      .str = &lib.str
    };

    if (!lib.parse.init(&parse_ctx)) {
      fprintf(stderr, "Failed to initialize siglatchd lib.parse\n");
      goto fail;
    }
  }
  parse_initialized = 1;

  lib.unicode.init();
  unicode_initialized = 1;

  {
    PrintContext print_ctx = {
      .unicode = &lib.unicode
    };
    lib.print.init(&print_ctx);
  }
  print_initialized = 1;

  {
    UtilsContext utils_ctx = {
      .print = &lib.print
    };
    utils->init(&utils_ctx);
  }
  utils_initialized = 1;

  {
    LogContext log_ctx = {
      .time = &lib.time,
      .print = &lib.print
    };
    lib.log.init(log_ctx);
  }
  log_initialized = 1;

  lib.hmac.init();
  hmac_initialized = 1;

  if (!lib.nonce.init()) {
    fprintf(stderr, "Failed to initialize siglatchd lib.nonce\n");
    goto fail;
  }
  nonce_initialized = 1;

  if (!lib.signal.init()) {
    fprintf(stderr, "Failed to initialize siglatchd lib.signal\n");
    goto fail;
  }
  signal_initialized = 1;

  {
    FileLibContext file_ctx = {
      .print = &lib.print,
      .auto_print_errors = true,
      .allow_unicode = true
    };
    lib.file.init(&file_ctx);
  }
  file_initialized = 1;

  {
    SiglatchOpenSSLContext openssl_ctx = {
      .log = &lib.log,
      .file = &lib.file,
      .hmac = &lib.hmac,
      .print = &lib.print
    };
    if (lib.openssl.init(&openssl_ctx) != 0) {
      fprintf(stderr, "Failed to initialize siglatchd lib.openssl\n");
      goto fail;
    }
  }
  openssl_initialized = 1;

  return 1;

fail:
  if (openssl_initialized) {
    lib.openssl.shutdown();
  }
  if (file_initialized) {
    lib.file.shutdown();
  }
  if (nonce_initialized) {
    lib.nonce.shutdown();
  }
  if (signal_initialized) {
    lib.signal.shutdown();
  }
  if (hmac_initialized) {
    lib.hmac.shutdown();
  }
  if (log_initialized) {
    lib.log.shutdown();
  }
  if (utils_initialized) {
    utils->shutdown();
  }
  if (print_initialized) {
    lib.print.shutdown();
  }
  if (unicode_initialized) {
    lib.unicode.shutdown();
  }
  if (parse_initialized) {
    lib.parse.shutdown();
  }
  if (argv_initialized) {
    lib.argv.shutdown();
  }
  if (str_initialized) {
    lib.str.shutdown();
  }
  if (process_initialized) {
    lib.process.shutdown();
  }
  if (net_initialized) {
    if (m7mux_initialized) {
      lib.m7mux.shutdown();
    }
    if (codec_context_initialized) {
      codec_context_lib->shutdown();
    }
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
  lib.openssl.shutdown();
  lib.signal.shutdown();
  lib.nonce.shutdown();
  lib.hmac.shutdown();

  lib.log.shutdown();
  lib.parse.shutdown();
  lib.argv.shutdown();
  get_lib_utils()->shutdown();
  lib.print.shutdown();
  lib.unicode.shutdown();
  lib.time.shutdown();
  lib.m7mux.shutdown();
  shared_knock_codec_context_shutdown();
  lib.net.shutdown();
  lib.str.shutdown();
}
