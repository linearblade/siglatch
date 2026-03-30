/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "openssl.h"

static const SiglatchOpenSSL_Lib siglatch_openssl_instance = {
    .init                   = siglatch_openssl_init,
    .shutdown               = siglatch_openssl_shutdown,
    .set_context            = siglatch_openssl_set_context,

    .session_init           = siglatch_openssl_session_init,
    .session_free           = siglatch_openssl_session_free,
    .session_readPrivateKey = siglatch_openssl_session_readPrivateKey,
    .session_readPublicKey  = siglatch_openssl_session_readPublicKey,
    .session_readHMAC       = siglatch_openssl_session_readHMAC,
    .session_encrypt        = siglatch_openssl_session_encrypt,
    .session_decrypt        = siglatch_openssl_session_decrypt,
    .session_decrypt_strerror = siglatch_openssl_decrypt_strerror,
    .sign                   = siglatch_openssl_sign,
    .digest_array           = siglatch_openssl_digest_array,
    .aesgcm_encrypt         = siglatch_openssl_aesgcm_encrypt,
    .aesgcm_decrypt         = siglatch_openssl_aesgcm_decrypt
};

const SiglatchOpenSSL_Lib *get_siglatch_openssl(void) {
    return &siglatch_openssl_instance;
}
