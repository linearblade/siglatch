/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

// payload_digest.h

#ifndef SIGLATCH_PAYLOAD_DIGEST_H
#define SIGLATCH_PAYLOAD_DIGEST_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "payload.h"  // For KnockPacket

typedef struct {
  void (*init)(void);                               // Library init
  void (*shutdown)(void);                           // Library shutdown
  int  (*generate)(const KnockPacket *pkt, uint8_t *out_digest /* 32 bytes */);  // Create digest
  int  (*sign)(EVP_PKEY *privkey, const uint8_t *digest, uint8_t *out_signature); // Sign digest
  int  (*validate)(EVP_PKEY *pubkey, const uint8_t *digest, const uint8_t *signature); // Validate signature
} PayloadDigest;
/*
typedef struct {
  void (*init)(void);                             // Library init (optional, currently a no-op)
  void (*shutdown)(void);                         // Library shutdown (optional)
  int  (*generate)(const KnockPacket *pkt, uint8_t *out_digest ); // 32 bytes  // Create digest
  int  (*sign)(EVP_PKEY *privkey, KnockPacket *pkt);                             // Sign packet
  int  (*validate)(EVP_PKEY *pubkey, const KnockPacket *pkt);                    // Validate signature
} PayloadDigest;
*/
// Accessor
const PayloadDigest *get_payload_digest_lib(void);

#endif // SIGLATCH_PAYLOAD_DIGEST_H
