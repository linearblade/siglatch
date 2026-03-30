/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_AESGCM_H
#define LIB_SIGLATCH_OPENSSL_AESGCM_H

#include <stddef.h>
#include <stdint.h>

#define SL_OPENSSL_AESGCM_KEY_LEN_128 16u
#define SL_OPENSSL_AESGCM_KEY_LEN_192 24u
#define SL_OPENSSL_AESGCM_KEY_LEN_256 32u
#define SL_OPENSSL_AESGCM_NONCE_LEN   12u
#define SL_OPENSSL_AESGCM_TAG_LEN     16u

int siglatch_openssl_aesgcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len,
    uint8_t *tag, size_t tag_len);

int siglatch_openssl_aesgcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag, size_t tag_len,
    uint8_t *plaintext, size_t *plaintext_len);

#endif // LIB_SIGLATCH_OPENSSL_AESGCM_H
