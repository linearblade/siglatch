// payload_digest.c

#include <openssl/evp.h>
#include <string.h>
#include "payload_digest.h"
#include "payload.h"
#include "utils.h"
// ── Internal implementations ──────────────────────

void payload_digest_init(void) {
    // Placeholder: no initialization needed yet
    // If future dynamic configuration is needed, add here
}

void payload_digest_shutdown(void) {
    // Placeholder: no teardown needed
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

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Hash fields in strict order
    EVP_DigestUpdate(ctx, &pkt->version, sizeof(pkt->version));
    EVP_DigestUpdate(ctx, &pkt->timestamp, sizeof(pkt->timestamp));
    EVP_DigestUpdate(ctx, &pkt->user_id, sizeof(pkt->user_id));
    EVP_DigestUpdate(ctx, &pkt->action_id, sizeof(pkt->action_id));
    EVP_DigestUpdate(ctx, &pkt->challenge, sizeof(pkt->challenge));
    EVP_DigestUpdate(ctx, &pkt->payload_len, sizeof(pkt->payload_len));
    EVP_DigestUpdate(ctx, pkt->payload, pkt->payload_len);

    unsigned int digest_len = 0;
    int ok = EVP_DigestFinal_ex(ctx, out_digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    if (!ok || digest_len != 32) {
        return 0;
    }

    return 1;
}

/**
 * payload_sign - Sign a precomputed SHA-256 digest using the private key.
 *
 * Parameters:
 *   privkey       - Pointer to loaded private EVP_PKEY.
 *   digest        - Pointer to 32-byte digest to sign.
 *   out_signature - Pointer to buffer (must be at least 32 bytes) to store the signature.
 *
 * Returns:
 *   1 on success,
 *   0 on failure.
 */
int payload_sign(EVP_PKEY *privkey, const uint8_t *digest, uint8_t *out_signature) {
    if (!privkey || !digest || !out_signature) {
        return 0;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pctx) {
        return 0;
    }

    if (EVP_PKEY_sign_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    size_t siglen = 0;
    if (EVP_PKEY_sign(pctx, NULL, &siglen, digest, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    uint8_t *sig = OPENSSL_malloc(siglen);
    if (!sig) {
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    if (EVP_PKEY_sign(pctx, sig, &siglen, digest, 32) <= 0) {
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    EVP_PKEY_CTX_free(pctx);

    // Store first 32 bytes of signature into out_signature
    if (siglen < 32) {
        OPENSSL_free(sig);
        return 0;
    }
    memcpy(out_signature, sig, 32);

    OPENSSL_free(sig);
    return 1;
}


/**
 * payload_validate - Validate a signature against a precomputed digest using a public key.
 *
 * Parameters:
 *   pubkey    - Pointer to loaded public EVP_PKEY.
 *   digest    - Pointer to 32-byte digest that was originally signed.
 *   signature - Pointer to signature to verify (expected to be 32 bytes, truncated).
 *
 * Returns:
 *   1 on successful verification,
 *   0 on failure (bad signature or error).
 */
int payload_validate(EVP_PKEY *pubkey, const uint8_t *digest, const uint8_t *signature) {
    if (!pubkey || !digest || !signature) {
        return 0;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!pctx) {
        return 0;
    }

    if (EVP_PKEY_verify_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    // We need to reconstruct full signature from truncated one (if needed) -- 
    // But for now, we assume the 32 bytes IS the full signature in our compact model.
    dumpDigest("PayloadDigest::Validating digest", digest, 32);
    dumpDigest("PayloadDigest::Validating signature", signature, 32);
    
    int result = EVP_PKEY_verify(pctx, signature, 32, digest, 32);
    EVP_PKEY_CTX_free(pctx);

    return (result == 1) ? 1 : 0;
}

// ── Singleton interface ───────────────────────────

static const PayloadDigest payload_digest = {
  .init = payload_digest_init,
  .shutdown = payload_digest_shutdown,
  .generate = payload_generateDigest,
  .sign = payload_sign,
  .validate = payload_validate
};

const PayloadDigest *get_payload_digest_lib(void) {
  return &payload_digest;
}
