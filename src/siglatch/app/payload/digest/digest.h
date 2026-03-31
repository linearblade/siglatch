/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_DIGEST_H
#define SIGLATCH_SERVER_APP_PAYLOAD_DIGEST_H

#include <stdint.h>

#include "../../../../shared/knock/packet.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*generate)(const KnockPacket *pkt, uint8_t *out_digest);
  int (*generate_oneshot)(const KnockPacket *pkt, uint8_t *out_digest);
  int (*sign)(const uint8_t *hmac_key, const uint8_t *digest, uint8_t *out_hmac);
  int (*validate)(const uint8_t *hmac_key, const uint8_t *digest, const uint8_t *signature);
} AppPayloadDigestLib;

int app_payload_digest_init(void);
void app_payload_digest_shutdown(void);
int app_payload_digest_generate(const KnockPacket *pkt, uint8_t *out_digest);
int app_payload_digest_generate_oneshot(const KnockPacket *pkt, uint8_t *out_digest);
int app_payload_digest_sign(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    uint8_t *out_hmac);
int app_payload_digest_validate(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    const uint8_t *signature);
const AppPayloadDigestLib *get_app_payload_digest_lib(void);

#endif
