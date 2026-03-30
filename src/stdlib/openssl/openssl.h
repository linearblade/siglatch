/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_H
#define LIB_SIGLATCH_OPENSSL_H

#include "../file.h"
#include "../log.h"
#include "digest/digest.h"
#include "aesgcm/aesgcm.h"
#include "hmac/hmac.h"
#include "session/session.h"
#include "rsa/rsa.h"
#include "../openssl_context.h"

// Struct holding all lib.openssl function pointers
typedef struct {
    int (*init)(SiglatchOpenSSLContext *ctx);          ///< Initialize OpenSSL library
    void (*shutdown)(void);                            ///< Shutdown OpenSSL library
    void (*set_context)(SiglatchOpenSSLContext *ctx);   ///< Set/override library context

    // Session helpers
  int (*session_init)(SiglatchOpenSSLSession *session);
  int (*session_free)(SiglatchOpenSSLSession *session);
  int (*session_readPrivateKey)(SiglatchOpenSSLSession *session, const char *filename); ///< Load a private key into session
  int (*session_readPublicKey)(SiglatchOpenSSLSession *session, const char *filename);  ///< Load a public key into session
  int (*session_readHMAC)(SiglatchOpenSSLSession *session, const char *filename);       ///< Load an HMAC key into session
  int (*session_encrypt)(SiglatchOpenSSLSession *session, const unsigned char *msg, size_t msg_len, unsigned char *out_buf, size_t *out_len);
  int (*session_decrypt)(SiglatchOpenSSLSession *session, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
  const char *(*session_decrypt_strerror)(int code);
  // Signing helper
  int (*sign)(SiglatchOpenSSLSession *session, const uint8_t *digest, uint8_t *out_signature); ///< Sign a digest using session key
  int (*digest_array)(const DigestItem *items, size_t item_count, uint8_t *out_digest);
  // AEAD helper
  int (*aesgcm_encrypt)(const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t *ciphertext_len,
                        uint8_t *tag, size_t tag_len);
  int (*aesgcm_decrypt)(const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *plaintext, size_t *plaintext_len);

} SiglatchOpenSSL_Lib;

// Getter for the OpenSSL library singleton
const SiglatchOpenSSL_Lib *get_siglatch_openssl(void);

#endif // LIB_SIGLATCH_OPENSSL_H
