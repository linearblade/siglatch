/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef MAIN_HELPERS_H
#define MAIN_HELPERS_H

#include "../stdlib/openssl_session.h" // for SiglatchOpenSSLSession
#include "../stdlib/payload.h"          // (your KnockPacket struct, etc.)
#include "parse_opts.h"
/**
 * Build a KnockPacket from a message.
 */
int structurePacket(KnockPacket *pkt_out, const uint8_t *payload, size_t len,  uint16_t user_id, uint8_t action_id) ;
//old way during testing
//int structurePacket(KnockPacket *pkt_out, const char *payload_data, uint16_t user_id, uint8_t action_id, int is_text);
/**
 * Initialize a basic user OpenSSL session.
 */
int init_user_openssl_session(const Opts *opts, SiglatchOpenSSLSession *session);
/**
 * Sign a packet
 **/
int signPacket(SiglatchOpenSSLSession *session, KnockPacket *pkt);

/**
 * @brief Signs the KnockPacket based on the selected HMAC mode.
 *
 * This wrapper handles the logic for different HMAC signing modes, including:
 * - HMAC_MODE_NORMAL: Performs standard cryptographic HMAC signing using session key.
 * - HMAC_MODE_DUMMY: Fills the HMAC field with a fixed dummy value (0x42) for testing.
 * - HMAC_MODE_NONE: Zeros out the HMAC field, skipping signature entirely.
 *
 * Logging is routed through standard LOG macros for each case.
 * Returns 1 on success, 0 on failure (and logs an error).
 *
 * @param opts     Parsed runtime options (contains hmac_mode).
 * @param session  OpenSSL session context, must contain HMAC key.
 * @param pkt      KnockPacket to be signed (HMAC will be modified in place).
 * @return int     1 on success, 0 on failure.
 */
int signWrapper(const Opts *opts, SiglatchOpenSSLSession *session, KnockPacket *pkt);


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


/**
 * @brief Prepares the payload for transmission, depending on mode.
 *
 * In dead-drop mode, copies the raw payload buffer.
 * In structured mode, serializes the KnockPacket into packed format.
 *
 * @param opts       Runtime options (for mode and raw payload)
 * @param pkt        Pointer to KnockPacket (used in structured mode)
 * @param packed     Output buffer for transmission payload
 * @param packed_len Output: number of bytes written to `packed`
 * @return int       1 on success, 0 on failure
 */
int structureOrDeadDrop(const Opts *opts, const KnockPacket *pkt,
			uint8_t *packed, int *packed_len);

#endif // MAIN_HELPERS_H
