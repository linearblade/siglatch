
#ifndef SIGLATCH_LIB_H
#define SIGLATCH_LIB_H

#include "../stdlib/log.h"
#include "../stdlib/time.h"
#include "../stdlib/payload.h"
#include "../stdlib/payload_digest.h"
#include "../stdlib/hmac_key.h"
#include "../stdlib/file.h"
#include "../stdlib/openssl.h"
#include "config.h"
#include "nonce_cache.h"

#if defined(__GNUC__) || defined(__clang__)
  #define UNUSED_FN __attribute__((unused))
#elif defined(_MSC_VER)
  #define UNUSED_FN __pragma(warning(suppress:4505))  // disables "unreferenced function"
#else
  #define UNUSED_FN
#endif

/**
 * @file lib.h
 * @brief Singleton system library registry for siglatch runtime.
 *
 * Provides centralized access to all runtime subsystems such as logging,
 * time, configuration, and future extensions. This acts as a globally
 * accessible service locator.
 */

typedef struct {
  ConfigLib config;
  Logger log;
  TimeLib time;
  NonceCache nonce;
  Payload payload;
  PayloadDigest payload_digest;
  HMACKey hmac;
  FileLib file;
  SiglatchOpenSSL_Lib openssl;
  
} Lib;

extern Lib lib;

void init_lib(void);
void shutdown_lib(void);



/**
 * 🔍 Logging Convenience Macros
 *
 * These macros provide short, readable access to the global logger via `lib.log`.
 * Use them to standardize logging behavior across the codebase — debug to screen,
 * log to file, or both.
 *
 * 🧾 What These Do:
 * ┌────────┬──────────────────────────────┬────────────────────────────────────┐
 * │ Macro  │ Expands To                   │ 🧠 Use for...                      │
 * ├────────┼──────────────────────────────┼────────────────────────────────────┤
 * │ LOG    │ lib.log                      │ Full access to logger struct       │
 * │ LOGI() │ lib.log.info(...)            │ 📜 Log-only (audit, config, events)│
 * │ LOGD() │ lib.log.debug(...)           │ 🐞 Debug to screen only            │
 * │ LOGB() │ lib.log.info_screen(...)     │ 🔔 Log + screen (critical events)  │
 * └────────┴──────────────────────────────┴────────────────────────────────────┘
 *
 * 🧪 Example Usage:
 *   LOGI("Granted access to %s\n", ip);         // Log only
 *   LOGD("Raw payload: %s\n", hex);             // Debug only
 *   LOGB("🚀 Startup complete on port %d\n", p); // Both
 */
#define LOG     lib.log

#define LOGE(...) lib.log.emit(LOG_ERROR, 1, __VA_ARGS__)
#define LOGW(...) lib.log.emit(LOG_WARN,  1, __VA_ARGS__)
#define LOGI(...) lib.log.emit(LOG_INFO,  0, __VA_ARGS__)
#define LOGD(...) lib.log.emit(LOG_DEBUG, 1, __VA_ARGS__)
#define LOGT(...) lib.log.emit(LOG_TRACE, 1, __VA_ARGS__)
#define LOGPERR(msg) lib.log.perror(msg)



#endif // SIGLATCH_LIB_H
