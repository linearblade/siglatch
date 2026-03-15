/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "digest.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <string.h>

#include "../../stdlib/utils.h"

static SharedKnockDigestContext g_shared_knock_digest_ctx = {0};

int shared_knock_digest_init(const SharedKnockDigestContext *ctx) {
  if (!ctx || !ctx->openssl) {
    return 0;
  }

  g_shared_knock_digest_ctx = *ctx;
  return 1;
}

void shared_knock_digest_shutdown(void) {
  g_shared_knock_digest_ctx = (SharedKnockDigestContext){0};
}

int shared_knock_digest_generate(const KnockPacket *pkt, uint8_t *out_digest) {
  DigestItem items[] = {
    {NULL, 0},
    {NULL, 0},
    {NULL, 0},
    {NULL, 0},
    {NULL, 0},
    {NULL, 0},
    {NULL, 0}
  };
  size_t item_count = 0;

  if (!pkt || !out_digest || !g_shared_knock_digest_ctx.openssl) {
    return 0;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return 0;
  }

  items[0] = (DigestItem){&pkt->version, sizeof(pkt->version)};
  items[1] = (DigestItem){&pkt->timestamp, sizeof(pkt->timestamp)};
  items[2] = (DigestItem){&pkt->user_id, sizeof(pkt->user_id)};
  items[3] = (DigestItem){&pkt->action_id, sizeof(pkt->action_id)};
  items[4] = (DigestItem){&pkt->challenge, sizeof(pkt->challenge)};
  items[5] = (DigestItem){&pkt->payload_len, sizeof(pkt->payload_len)};
  items[6] = (DigestItem){pkt->payload, pkt->payload_len};
  item_count = sizeof(items) / sizeof(items[0]);

  return g_shared_knock_digest_ctx.openssl->digest_array(items, item_count, out_digest);
}

int shared_knock_digest_generate_oneshot(const KnockPacket *pkt, uint8_t *out_digest) {
  EVP_MD_CTX *ctx = NULL;
  unsigned int digest_len = 0;
  int result = 0;

  if (!pkt || !out_digest) {
    return 0;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return 0;
  }

  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return 0;
  }

  do {
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->version, sizeof(pkt->version)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->timestamp, sizeof(pkt->timestamp)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->user_id, sizeof(pkt->user_id)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->action_id, sizeof(pkt->action_id)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->challenge, sizeof(pkt->challenge)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, &pkt->payload_len, sizeof(pkt->payload_len)) != 1) {
      break;
    }
    if (EVP_DigestUpdate(ctx, pkt->payload, pkt->payload_len) != 1) {
      break;
    }
    if (EVP_DigestFinal_ex(ctx, out_digest, &digest_len) != 1) {
      break;
    }
    if (digest_len != 32) {
      break;
    }
    result = 1;
  } while (0);

  EVP_MD_CTX_free(ctx);
  return result;
}

int shared_knock_digest_sign(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    uint8_t *out_hmac) {
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("digest", "SHA256", 0),
    OSSL_PARAM_END
  };
  size_t out_len = 0;
  int result = 0;

  if (!hmac_key || !digest || !out_hmac) {
    return 0;
  }

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!mac) {
    return 0;
  }

  ctx = EVP_MAC_CTX_new(mac);
  if (!ctx) {
    EVP_MAC_free(mac);
    return 0;
  }

  if (EVP_MAC_init(ctx, hmac_key, 32, params) != 1) {
    goto cleanup;
  }
  if (EVP_MAC_update(ctx, digest, 32) != 1) {
    goto cleanup;
  }
  if (EVP_MAC_final(ctx, out_hmac, &out_len, 32) != 1) {
    goto cleanup;
  }
  if (out_len != 32) {
    goto cleanup;
  }

  result = 1;

cleanup:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return result;
}

int shared_knock_digest_validate(
    const uint8_t *hmac_key,
    const uint8_t *digest,
    const uint8_t *signature) {
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("digest", "SHA256", 0),
    OSSL_PARAM_END
  };
  uint8_t computed_hmac[32] = {0};
  size_t computed_len = 0;
  int result = 0;

  if (!hmac_key || !digest || !signature) {
    return 0;
  }

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!mac) {
    return 0;
  }

  ctx = EVP_MAC_CTX_new(mac);
  if (!ctx) {
    EVP_MAC_free(mac);
    return 0;
  }

  if (EVP_MAC_init(ctx, hmac_key, 32, params) != 1) {
    goto cleanup;
  }
  if (EVP_MAC_update(ctx, digest, 32) != 1) {
    goto cleanup;
  }
  if (EVP_MAC_final(ctx, computed_hmac, &computed_len, sizeof(computed_hmac)) != 1) {
    goto cleanup;
  }
  if (computed_len != 32) {
    goto cleanup;
  }

  dumpDigest("PayloadDigest::Validating digest", digest, 32);
  dumpDigest("PayloadDigest::Validating signature", signature, 32);
  dumpDigest("PayloadDigest::Recomputed signature", computed_hmac, 32);

  if (CRYPTO_memcmp(signature, computed_hmac, 32) != 0) {
    goto cleanup;
  }

  result = 1;

cleanup:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return result;
}

static const SharedKnockDigestLib shared_knock_digest = {
  .init = shared_knock_digest_init,
  .shutdown = shared_knock_digest_shutdown,
  .generate = shared_knock_digest_generate,
  .generate_oneshot = shared_knock_digest_generate_oneshot,
  .sign = shared_knock_digest_sign,
  .validate = shared_knock_digest_validate
};

const SharedKnockDigestLib *get_shared_knock_digest_lib(void) {
  return &shared_knock_digest;
}
