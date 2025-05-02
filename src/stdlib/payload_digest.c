// payload_digest.c

#include <openssl/core_names.h>  // For "digest" name string
#include <openssl/evp.h>
#include <string.h>
#include "payload_digest.h"
#include "payload.h"
#include "utils.h"
// ── Internal implementations ──────────────────────
static PayloadDigestContext g_payload_digest_ctx = {0}; // Static global copy

void payload_digest_init(const PayloadDigestContext *ctx) {
    if (!ctx) {
        return; // Ignore NULL initialization
    }

    g_payload_digest_ctx = *ctx; // Copy by value
}
void payload_digest_shutdown(void) {
    g_payload_digest_ctx = (PayloadDigestContext){0}; // Reset the static context
}

/**
 * payload_generateDigest - Computes a SHA-256 digest over critical fields of a KnockPacket.
 *
 * Parameters:
 *   pkt        - Pointer to KnockPacket to hash.
 *   out_digest - Pointer to buffer (32 bytes) to store output digest.
 *
 * Returns:
 *   1 on success,
 *   0 on failure.
 */

int payload_generateDigest(const KnockPacket *pkt, uint8_t *out_digest) {
    if (!pkt || !out_digest) {
        return 0;
    }

    DigestItem items[] = {
        { &pkt->version,    sizeof(pkt->version)    },
        { &pkt->timestamp,  sizeof(pkt->timestamp)  },
        { &pkt->user_id,    sizeof(pkt->user_id)    },
        { &pkt->action_id,  sizeof(pkt->action_id)  },
        { &pkt->challenge,  sizeof(pkt->challenge)  },
        { &pkt->payload_len, sizeof(pkt->payload_len) },
        { pkt->payload,     pkt->payload_len        }
    };

    size_t item_count = sizeof(items) / sizeof(items[0]);

    return g_payload_digest_ctx.openssl->digest_array(items, item_count, out_digest);
}

int payload_generateDigest_oneshot(const KnockPacket *pkt, uint8_t *out_digest) {
    if (!pkt || !out_digest) {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    int result = 0; // Assume failure

    do {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) break;

        // Hash fields in strict, consistent order
        if (EVP_DigestUpdate(ctx, &pkt->version, sizeof(pkt->version)) != 1) break;
        if (EVP_DigestUpdate(ctx, &pkt->timestamp, sizeof(pkt->timestamp)) != 1) break;
        if (EVP_DigestUpdate(ctx, &pkt->user_id, sizeof(pkt->user_id)) != 1) break;
        if (EVP_DigestUpdate(ctx, &pkt->action_id, sizeof(pkt->action_id)) != 1) break;
        if (EVP_DigestUpdate(ctx, &pkt->challenge, sizeof(pkt->challenge)) != 1) break;
        if (EVP_DigestUpdate(ctx, &pkt->payload_len, sizeof(pkt->payload_len)) != 1) break;
        if (EVP_DigestUpdate(ctx, pkt->payload, pkt->payload_len) != 1) break;

        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(ctx, out_digest, &digest_len) != 1) break;
        if (digest_len != 32) break;

        // If we got here, everything succeeded
        result = 1;
    } while (0);

    EVP_MD_CTX_free(ctx);
    return result;
}

/**
 * payload_sign - Sign a precomputed SHA-256 digest using a 32-byte HMAC key.
 *
 * Parameters:
 *   hmac_key      - Pointer to 32-byte HMAC key.
 *   digest        - Pointer to 32-byte digest to sign.
 *   out_signature - Pointer to buffer (must be at least 32 bytes) to store the HMAC output.
 *
 * Returns:
 *   1 on success,
 *   0 on failure.
 */
int payload_sign(const uint8_t *hmac_key, const uint8_t *digest, uint8_t *out_signature) {
    if (!hmac_key || !digest || !out_signature) {
        return 0;
    }

    int result = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    size_t out_len = 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        return 0;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return 0;
    }

    // Set up HMAC context: specify SHA256 digest
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };

    if (EVP_MAC_init(ctx, hmac_key, 32, params) != 1) {
        goto cleanup;
    }

    if (EVP_MAC_update(ctx, digest, 32) != 1) {
        goto cleanup;
    }

    if (EVP_MAC_final(ctx, out_signature, &out_len, 32) != 1) {
        goto cleanup;
    }

    if (out_len != 32) {
        goto cleanup;
    }

    result = 1;  // Success!

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return result;
}

#include <openssl/evp.h>
#include <openssl/core_names.h>  // For OSSL_PARAM strings

/**
 * payload_validate - Validate a signed HMAC against a precomputed digest.
 *
 * Parameters:
 *   hmac_key  - Pointer to 32-byte HMAC key.
 *   digest    - Pointer to 32-byte digest to validate.
 *   signature - Pointer to received signature (expected 32 bytes HMAC).
 *
 * Returns:
 *   1 on successful verification,
 *   0 on failure (bad signature or error).
 */
int payload_validate(const uint8_t *hmac_key, const uint8_t *digest, const uint8_t *signature) {
  if (!hmac_key || !digest || !signature) {
    return 0;
  }

  int result = 0;
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  uint8_t computed_hmac[32] = {0};
  size_t computed_len = 0;

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!mac) {
    return 0;
  }

  ctx = EVP_MAC_CTX_new(mac);
  if (!ctx) {
    EVP_MAC_free(mac);
    return 0;
  }

  OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("digest", "SHA256", 0),
    OSSL_PARAM_END
  };

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

  result = 1;  // Successful validation!

 cleanup:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return result;
}
// ── Singleton interface ───────────────────────────

static const PayloadDigest payload_digest = {
  .init = payload_digest_init,
  .shutdown = payload_digest_shutdown,
  .generate = payload_generateDigest,
  .generate_oneshot = payload_generateDigest_oneshot,
  .sign = payload_sign,
  .validate = payload_validate
};

const PayloadDigest *get_payload_digest_lib(void) {
  return &payload_digest;
}
