/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_RSA_H
#define LIB_SIGLATCH_OPENSSL_RSA_H

#include <stddef.h>
#include <stdint.h>

#include "../session/session.h"

#define SL_SSL_DECRYPT_OK               0
#define SL_SSL_DECRYPT_ERR_ARGS       -1
#define SL_SSL_DECRYPT_ERR_CTX_ALLOC  -2
#define SL_SSL_DECRYPT_ERR_INIT       -3
#define SL_SSL_DECRYPT_ERR_PADDING    -4
#define SL_SSL_DECRYPT_ERR_LEN_QUERY  -5
#define SL_SSL_DECRYPT_ERR_DECRYPT    -6

int siglatch_openssl_session_encrypt(SiglatchOpenSSLSession *session,
                                     const unsigned char *msg, size_t msg_len,
                                     unsigned char *out_buf, size_t *out_len);
int siglatch_openssl_session_decrypt(
    SiglatchOpenSSLSession *session,
    const unsigned char *input, size_t input_len,
    unsigned char *output, size_t *output_len);
const char *siglatch_openssl_decrypt_strerror(int code);

#endif // LIB_SIGLATCH_OPENSSL_RSA_H
