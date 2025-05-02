#ifndef LIB_SIGLATCH_OPENSSL_SESSION_H
#define LIB_SIGLATCH_OPENSSL_SESSION_H

#include <stddef.h>   // For size_t
#include <stdint.h>   // For uint8_t
#include <stdbool.h>  // For bool
#include <openssl/evp.h>  // For EVP_PKEY and EVP_PKEY_CTX

#include "openssl_context.h" // Pulls in SiglatchOpenSSLContext

// OpenSSL session context structure
typedef struct SiglatchOpenSSLSession {
  SiglatchOpenSSLContext *parent_ctx; ///< Pointer to the global OpenSSL context (file, log, etc.)

  EVP_PKEY *public_key;    ///< Public key (for encrypting or verifying signatures)
  EVP_PKEY *private_key;   ///< Private key (for decrypting or signing)

  EVP_PKEY_CTX *public_key_ctx;    ///< Context for public key operations
  EVP_PKEY_CTX *private_key_ctx;   ///< Context for private key operations

  uint8_t hmac_key[64];    ///< Raw HMAC key storage (if session is used for HMAC operations)
  size_t hmac_key_len;     ///< Length of the loaded HMAC key (0 if none)

  bool owns_ctx;           ///< True if the session is responsible for freeing its context
} SiglatchOpenSSLSession;

#endif // LIB_SIGLATCH_OPENSSL_SESSION_H
