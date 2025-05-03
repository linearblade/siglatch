/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_PAYLOAD_DIGEST_H
#define SIGLATCH_PAYLOAD_DIGEST_H

#include <stdint.h>
#include <stddef.h>
#include "payload.h"  // For KnockPacket
//#include "file.h"
#include "log.h"
//#include "hmac_key.h"
#include "openssl.h"

// OpenSSL library context
typedef struct {
  //const FileLib *file; ///< Pointer to file library (e.g., for reading keys from disk)
  const  Logger *log;   ///< Pointer to logging library (for error reporting)
  const  SiglatchOpenSSL_Lib *openssl;   ///< Pointer to logging library (for error reporting)
  //const HMACKey * hmac; //< pointer to hmac key reader
  // Future: random number generation lib, config flags, etc.
} PayloadDigestContext;



typedef struct {
  void (*init)(const PayloadDigestContext * ctx);  // Optional future init
  void (*shutdown)(void); // Optional future shutdown

  /**
   * generate
   * Generate a SHA-256 digest over a KnockPacket.
   *
   * Parameters:
   *   pkt        - Pointer to KnockPacket.
   *   out_digest - Output buffer for 32-byte digest.
   *
   * Returns:
   *   1 on success, 0 on failure.
   */
  int (*generate)(const KnockPacket *pkt, uint8_t *out_digest);
  int (*generate_oneshot)(const KnockPacket *pkt, uint8_t *out_digest); //legacy version , kept for testing
  /**
   * sign
   * Sign a digest using a 32-byte HMAC key.
   *
   * Parameters:
   *   hmac_key   - 32-byte HMAC key.
   *   digest     - 32-byte digest to sign.
   *   out_hmac   - Output buffer for 32-byte signed HMAC.
   *
   * Returns:
   *   1 on success, 0 on failure.
   */
  int (*sign)(const uint8_t *hmac_key, const uint8_t *digest, uint8_t *out_hmac);

  /**
   * validate
   * Validate a signed HMAC against a digest.
   *
   * Parameters:
   *   hmac_key   - 32-byte HMAC key.
   *   digest     - 32-byte digest to validate.
   *   signature  - 32-byte received HMAC signature.
   *
   * Returns:
   *   1 on success (valid), 0 on failure (invalid).
   */
  int (*validate)(const uint8_t *hmac_key, const uint8_t *digest, const uint8_t *signature);

} PayloadDigest;

// Accessor
const PayloadDigest *get_payload_digest_lib(void);

#endif // SIGLATCH_PAYLOAD_DIGEST_H
