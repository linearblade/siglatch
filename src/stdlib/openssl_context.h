#ifndef LIB_SIGLATCH_OPENSSL_CONTEXT_H
#define LIB_SIGLATCH_OPENSSL_CONTEXT_H

#include "file.h"
#include "log.h"
#include "hmac_key.h"

// OpenSSL library context
typedef struct {
  const FileLib *file; ///< Pointer to file library (e.g., for reading keys from disk)
  const  Logger *log;   ///< Pointer to logging library (for error reporting)
  const HMACKey * hmac; //< pointer to hmac key reader
  // Future: random number generation lib, config flags, etc.
} SiglatchOpenSSLContext;

#endif // LIB_SIGLATCH_OPENSSL_H
