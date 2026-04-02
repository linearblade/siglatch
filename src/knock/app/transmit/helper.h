/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_TRANSMIT_HELPER_H
#define SIGLATCH_KNOCK_APP_TRANSMIT_HELPER_H

#include <stddef.h>
#include <stdint.h>

#include "../../../stdlib/openssl/session/session.h" // for SiglatchOpenSSLSession
#include "../opts/contract.h"
/**
 * Initialize a basic user OpenSSL session.
 */
int init_user_openssl_session(const Opts *opts, SiglatchOpenSSLSession *session);


/**
 * @brief Encrypts the packed payload if encryption is enabled.
 *
 * If opts->encrypt is true, calls OpenSSL encryption.
 * If false, copies the raw packed data directly to the output buffer.
 *
 * @param opts      Runtime configuration (encrypt flag)
 * @param session   Initialized OpenSSL session (must contain public key)
 * @param input     Input data to encrypt (packed KnockPacket)
 * @param input_len Length of input data
 * @param out_buf   Output buffer to hold encrypted or raw data
 * @param out_len   Output length written
 * @return int      1 on success, 0 on failure
 */
int encryptWrapper(const Opts *opts, SiglatchOpenSSLSession *session,
		    const uint8_t *input, size_t input_len,
		    unsigned char *out_buf, size_t *out_len);

#endif // SIGLATCH_KNOCK_APP_TRANSMIT_HELPER_H
