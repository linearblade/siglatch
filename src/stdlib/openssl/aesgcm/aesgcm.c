/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "aesgcm.h"

#include <limits.h>
#include <openssl/evp.h>

static const EVP_CIPHER *_siglatch_openssl_aesgcm_cipher_for_key_len(size_t key_len);
static int _siglatch_openssl_aesgcm_validate_sizes(size_t key_len, size_t nonce_len, size_t aad_len, size_t data_len, size_t tag_len);

static const EVP_CIPHER *_siglatch_openssl_aesgcm_cipher_for_key_len(size_t key_len) {
  switch (key_len) {
    case SL_OPENSSL_AESGCM_KEY_LEN_128:
      return EVP_aes_128_gcm();
    case SL_OPENSSL_AESGCM_KEY_LEN_192:
      return EVP_aes_192_gcm();
    case SL_OPENSSL_AESGCM_KEY_LEN_256:
      return EVP_aes_256_gcm();
    default:
      return NULL;
  }
}

static int _siglatch_openssl_aesgcm_validate_sizes(size_t key_len, size_t nonce_len, size_t aad_len, size_t data_len, size_t tag_len) {
  if (key_len > (size_t)INT_MAX ||
      nonce_len > (size_t)INT_MAX ||
      aad_len > (size_t)INT_MAX ||
      data_len > (size_t)INT_MAX ||
      tag_len > (size_t)INT_MAX) {
    return 0;
  }

  return 1;
}

int siglatch_openssl_aesgcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len,
    uint8_t *tag, size_t tag_len) {
  const EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int result = 0;

  if (!key || !nonce || !plaintext || !ciphertext || !ciphertext_len || !tag) {
    return 0;
  }
  if (aad_len > 0 && !aad) {
    return 0;
  }
  if (plaintext_len > 0 && !plaintext) {
    return 0;
  }
  if (!_siglatch_openssl_aesgcm_validate_sizes(key_len, nonce_len, aad_len, plaintext_len, tag_len)) {
    return 0;
  }
  if (tag_len != SL_OPENSSL_AESGCM_TAG_LEN) {
    return 0;
  }

  cipher = _siglatch_openssl_aesgcm_cipher_for_key_len(key_len);
  if (!cipher) {
    return 0;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return 0;
  }

  do {
    int len = 0;
    int total_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
      break;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
      break;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
      break;
    }

    if (aad_len > 0) {
      if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        break;
      }
    }

    if (plaintext_len > 0) {
      if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        break;
      }
      total_len = len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
      break;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) != 1) {
      break;
    }

    *ciphertext_len = (size_t)total_len;
    result = 1;
  } while (0);

  EVP_CIPHER_CTX_free(ctx);
  return result;
}

int siglatch_openssl_aesgcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag, size_t tag_len,
    uint8_t *plaintext, size_t *plaintext_len) {
  const EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int result = 0;

  if (!key || !nonce || !ciphertext || !tag || !plaintext || !plaintext_len) {
    return 0;
  }
  if (aad_len > 0 && !aad) {
    return 0;
  }
  if (ciphertext_len > 0 && !ciphertext) {
    return 0;
  }
  if (!_siglatch_openssl_aesgcm_validate_sizes(key_len, nonce_len, aad_len, ciphertext_len, tag_len)) {
    return 0;
  }
  if (tag_len != SL_OPENSSL_AESGCM_TAG_LEN) {
    return 0;
  }

  cipher = _siglatch_openssl_aesgcm_cipher_for_key_len(key_len);
  if (!cipher) {
    return 0;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return 0;
  }

  do {
    int len = 0;
    int total_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
      break;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
      break;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
      break;
    }

    if (aad_len > 0) {
      if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        break;
      }
    }

    if (ciphertext_len > 0) {
      if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        break;
      }
      total_len = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag) != 1) {
      break;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
      break;
    }
    total_len += len;

    *plaintext_len = (size_t)total_len;
    result = 1;
  } while (0);

  EVP_CIPHER_CTX_free(ctx);
  return result;
}
