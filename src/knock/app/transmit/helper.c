/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "helper.h"

#include <stdio.h>
#include <string.h>

#include "../../lib.h"

int init_user_openssl_session(const Opts *opts, SiglatchOpenSSLSession *session) {
    int need_hmac = 0;
    int need_public_key = 0;

    if (!session ) {
        lib.log.console("NULL pointer passed to OpenSSL session initializer\n");
        return 0;
    }
    if (!opts ) {
        lib.log.console("NULL configuration pointer passed\n");
        return 0;
    }

    switch (opts->hmac_mode) {
        case HMAC_MODE_NORMAL:
            need_hmac = 1;
            break;
        case HMAC_MODE_DUMMY:
        case HMAC_MODE_NONE:
            need_hmac = 0;
            break;
        default:
            lib.log.console("Unknown HMAC mode: %d\n", opts->hmac_mode);
            return 0;
    }

    if (opts->encrypt) {
        need_public_key = 1;
    }

    if (!need_hmac && !need_public_key) {
        return 1;
    }

    if (!lib.openssl.session_init(session)) {
        lib.log.console("Failed to initialize OpenSSL session!\n");
        return 0;
    }

    if (need_hmac && !lib.openssl.session_readHMAC(session, opts->hmac_key_path)) {
        lib.log.console("Failed to load HMAC key!\n");
        return 0;
    }

    if (need_public_key && !lib.openssl.session_readPublicKey(session, opts->server_pubkey_path)) {
        lib.log.console("Failed to load public key!\n");
        return 0;
    }

    return 1;
}

int encryptWrapper(const Opts *opts, SiglatchOpenSSLSession *session,
                   const uint8_t *input, size_t input_len,
                   unsigned char *out_buf, size_t *out_len) {
  if (opts->encrypt) {
    if (!lib.openssl.session_encrypt(session, input, input_len, out_buf, out_len)) {
      LOGE("OpenSSL encryption failed\n");
      return 0;
    }
    LOGD("Encrypted payload (%zu bytes)\n", *out_len);
  } else {
    memcpy(out_buf, input, input_len);
    *out_len = input_len;
    LOGD("Sending raw payload (unencrypted, %zu bytes)\n", input_len);
  }

  return 1;
}
