/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_DIGEST_H
#define SIGLATCH_SHARED_KNOCK_DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "../../stdlib/log.h"
#include "../../stdlib/openssl.h"
#include "packet.h"

typedef struct {
  const Logger *log;
  const SiglatchOpenSSL_Lib *openssl;
} SharedKnockDigestContext;

typedef struct {
  int (*init)(const SharedKnockDigestContext *ctx);
  void (*shutdown)(void);
  int (*generate)(const KnockPacket *pkt, uint8_t *out_digest);
  int (*generate_oneshot)(const KnockPacket *pkt, uint8_t *out_digest);
  int (*sign)(const uint8_t *hmac_key, const uint8_t *digest, uint8_t *out_hmac);
  int (*validate)(const uint8_t *hmac_key, const uint8_t *digest, const uint8_t *signature);
} SharedKnockDigestLib;

int shared_knock_digest_init(const SharedKnockDigestContext *ctx);
void shared_knock_digest_shutdown(void);
int shared_knock_digest_generate(const KnockPacket *pkt, uint8_t *out_digest);
int shared_knock_digest_generate_oneshot(const KnockPacket *pkt, uint8_t *out_digest);
int shared_knock_digest_sign(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    uint8_t *out_hmac);
int shared_knock_digest_validate(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    const uint8_t *signature);
const SharedKnockDigestLib *get_shared_knock_digest_lib(void);

#endif
