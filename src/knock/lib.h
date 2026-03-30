/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#ifndef SIGLATCH_LIB_H
#define SIGLATCH_LIB_H

#include "../stdlib/log.h"
#include "../stdlib/time.h"
#include "../stdlib/random.h"
#include "../stdlib/hmac_key.h"
#include "../stdlib/file.h"
#include "../stdlib/nonce.h"
#include "../stdlib/signal.h"
#include "../stdlib/env.h"
#include "../stdlib/openssl.h"
#include "../stdlib/argv.h"
#include "../stdlib/parse/parse.h"
#include "../stdlib/str.h"
#include "../stdlib/net.h"
#include "../stdlib/protocol/udp/m7mux/m7mux.h"
#include "../stdlib/print.h"
#include "../stdlib/stdin.h"
#include "../stdlib/unicode.h"
/**
 * @file lib.h
 * @brief Singleton system library registry for siglatch runtime.
 *
 * Provides centralized access to all runtime subsystems such as logging,
 * time, configuration, and future extensions. This acts as a globally
 * accessible service locator.
 */

typedef struct {
  Logger log;
  TimeLib time;
  RandomLib random;
  HMACKey hmac;
  EnvLib env;
  FileLib file;
  NonceLib nonce;
  SignalLib signal;
  SiglatchOpenSSL_Lib openssl;
  ArgvLib argv;
  StrLib str;
  ParseLib parse;
  PrintLib print;
  StdinLib stdin;
  UnicodeLib unicode;
  NetLib net;
  M7MuxLib m7mux;
} Lib;

extern Lib lib;

int init_lib(void);
void shutdown_lib(void);



/**
 *  Logging Convenience Macros
 *
 * These macros provide short, readable access to the global logger via `lib.log`.
 * Use them to standardize logging behavior across the codebase - debug to screen,
 * log to file, or both.
 *
 *  What These Do:
 * +--------+------------------------------+------------------------------------+
 * | Macro  | Expands To                   |  Use for...                      |
 * +--------+------------------------------+------------------------------------+
 * | LOG    | lib.log                      | Full access to logger struct       |
 * | LOGI() | lib.log.info(...)            | Log-only (audit, config, events)|
 * | LOGD() | lib.log.debug(...)           | Debug to screen only            |
 * | LOGB() | lib.log.info_screen(...)     |  Log + screen (critical events)  |
 * +--------+------------------------------+------------------------------------+
 *
 * Example Usage:
 *   LOGI("Granted access to %s\n", ip);         // Log only
 *   LOGD("Raw payload: %s\n", hex);             // Debug only
 *   LOGB("Startup complete on port %d\n", p); // Both
 */
#define LOG     lib.log

#define LOGE(...) lib.log.emit(LOG_ERROR, 1, __VA_ARGS__)
#define LOGW(...) lib.log.emit(LOG_WARN,  1, __VA_ARGS__)
#define LOGI(...) lib.log.emit(LOG_INFO,  1, __VA_ARGS__)
#define LOGD(...) lib.log.emit(LOG_DEBUG, 1, __VA_ARGS__)
#define LOGT(...) lib.log.emit(LOG_TRACE, 1, __VA_ARGS__)
#define LOGPERR(msg) lib.log.perror(msg)



#endif // SIGLATCH_LIB_H
