/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "digest.h"

#include "../../../../shared/shared.h"

int app_payload_digest_init(void) {
  return shared.knock.digest.init &&
         shared.knock.digest.shutdown &&
         shared.knock.digest.generate &&
         shared.knock.digest.generate_oneshot &&
         shared.knock.digest.sign &&
         shared.knock.digest.validate;
}

void app_payload_digest_shutdown(void) {
}

int app_payload_digest_generate(const KnockPacket *pkt, uint8_t *out_digest) {
  return shared.knock.digest.generate(pkt, out_digest);
}

int app_payload_digest_generate_oneshot(const KnockPacket *pkt, uint8_t *out_digest) {
  return shared.knock.digest.generate_oneshot(pkt, out_digest);
}

int app_payload_digest_sign(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    uint8_t *out_hmac) {
  return shared.knock.digest.sign(hmac_key, digest, out_hmac);
}

int app_payload_digest_validate(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    const uint8_t *signature) {
  return shared.knock.digest.validate(hmac_key, digest, signature);
}

static const AppPayloadDigestLib app_payload_digest_instance = {
  .init = app_payload_digest_init,
  .shutdown = app_payload_digest_shutdown,
  .generate = app_payload_digest_generate,
  .generate_oneshot = app_payload_digest_generate_oneshot,
  .sign = app_payload_digest_sign,
  .validate = app_payload_digest_validate
};

const AppPayloadDigestLib *get_app_payload_digest_lib(void) {
  return &app_payload_digest_instance;
}
