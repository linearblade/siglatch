/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "digest.h"

#include <openssl/evp.h>

int siglatch_openssl_digest_array(const DigestItem *items, size_t item_count, uint8_t *out_digest) {
  if (!items || !out_digest || item_count == 0) {
    return 0;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return 0;
  }

  int result = 0;

  do {
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
      break;
    }

    for (size_t i = 0; i < item_count; ++i) {
      if (!items[i].data || items[i].size == 0) {
        continue;
      }
      if (EVP_DigestUpdate(ctx, items[i].data, items[i].size) != 1) {
        break;
      }
    }

    unsigned int digest_len = 0;
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
