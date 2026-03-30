/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "hmac.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

int siglatch_openssl_sign(SiglatchOpenSSLSession *session, const uint8_t *digest, uint8_t *out_signature) {
  if (!session || !digest || !out_signature) {
    return 0;
  }

  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  size_t out_len = 0;
  int result = 0;

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

  if (EVP_MAC_init(ctx, session->hmac_key, session->hmac_key_len, params) != 1) {
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

  result = 1;

cleanup:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return result;
}
