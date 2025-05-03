/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>  // herp a derp -- need this for constants :{ 

#include "config.h"
#include "decrypt.h"
#include "lib.h"
#include "../stdlib/utils.h"

/**
 * Initialize a SiglatchOpenSSLSession for decryption on the server.
 * This sets up the session with the server's private key only.
 * No HMAC or user-specific keys are attached — this must be done per packet if needed.
 *
 * @param cfg     Pointer to global server config (must contain valid master_privkey)
 * @param session Pointer to a session to initialize
 * @return 1 on success, 0 on failure
 */
int session_init_for_server(const siglatch_config *cfg, SiglatchOpenSSLSession *session) {
    if (!session) {
        lib.log.console("❌ NULL session pointer passed to server OpenSSL initializer\n");
        return 0;
    }

    if (!cfg || !cfg->current_server->priv_key) {
        lib.log.console("❌ Invalid configuration passed — missing master private key\n");
        return 0;
    }

    if (!lib.openssl.session_init(session)) {
        lib.log.console("❌ Failed to initialize OpenSSL session\n");
        return 0;
    }

    // Directly assign the already-loaded private key into the session
    session->private_key = cfg->current_server->priv_key;
    // Optional: clear any previous contexts, if needed

    return 1;
}

/**
 * @brief Attach user-specific keys to an OpenSSL session.
 *
 * This function configures a session object with user-specific cryptographic material.
 * It copies the user's normalized HMAC key into the session and assigns the user's
 * preloaded RSA public key for future signature verification or encryption.
 *
 * The session does not take ownership of the user's public key — it merely references it.
 * Key memory is managed by the user registry (cfg->users[]), and should not be freed by the session.
 *
 * @param session Pointer to an initialized SiglatchOpenSSLSession.
 * @param user Pointer to a loaded siglatch_user containing the HMAC key and public key.
 * @return 1 on success, 0 on failure (invalid pointers).
 */
int session_assign_to_user(SiglatchOpenSSLSession *session, const siglatch_user *user) {
  if (!session || !user) {
    LOGE("❌ session_assign_to_user: NULL session or user pointer");
    return 0;
  }

  // Copy pre-normalized HMAC key from user record
  memcpy(session->hmac_key, user->hmac_key, sizeof(session->hmac_key));
  session->hmac_key_len = 32;  // always 32 in your usage

  // Assign user public key (just link it — not copied or owned)
  session->public_key = user->pubkey;

  LOGT("🔑 Session now attached to user: %s\n", user->name);
  return 1;
}


/**
 * @brief Decrypt a received encrypted knock payload using an OpenSSL session.
 *
 * This is the main entry point for decrypting UDP payloads received by the server.
 * The session must be preconfigured with a valid RSA private key.
 *
 * @param session        Pointer to an initialized SiglatchOpenSSLSession (with private_key).
 * @param input          Encrypted input buffer.
 * @param input_len      Length of encrypted data.
 * @param output         Output buffer to write decrypted data.
 * @param output_len     Pointer to receive length of decrypted data.
 * @param error_msg_buf  Optional buffer for error string.
 * @param bufsize        Size of error_msg_buf.
 * @return 0 on success, negative error code on failure.
 */
int decrypt_knock(
    SiglatchOpenSSLSession *session,
    const unsigned char *input, size_t input_len,
    unsigned char *output, size_t *output_len,
    char *error_msg_buf, size_t bufsize
) {
    int rc = -1;

    #define SET_ERROR_AND_GOTO(_rc, _msg, ...)  \
        do { \
            if (error_msg_buf && bufsize > 0) { \
                snprintf(error_msg_buf, bufsize, _msg, ##__VA_ARGS__); \
            } \
            LOGE(_msg, ##__VA_ARGS__); \
            rc = (_rc); \
            goto cleanup; \
        } while (0)

    if (!session || !session->private_key || !input || !output || !output_len) {
        SET_ERROR_AND_GOTO(-1, "[decrypt] ❌ Invalid arguments to decrypt_knock\n");
    }

    if (!lib.openssl.session_decrypt(session, input, input_len, output, output_len)) {
        SET_ERROR_AND_GOTO(-2, "[decrypt] ❌ session_decrypt() failed\n");
    }

    rc = 0;  // Success

cleanup:
    return rc;
}

    //LOGT("🔓 Decrypted knock: '%s'\n", output);

/**
 * validateSignature - Verify the authenticity of a KnockPacket using the user's public key.
 *
 * This function reconstructs a SHA-256 digest over the critical fields of the KnockPacket,
 * and verifies the provided signature (stored in pkt->hmac) using the user's preloaded
 * public key (EVP_PKEY) stored in the configuration.
 *
 * Fields included in the digest (in strict order):
 * - version
 * - timestamp
 * - user_id
 * - action_id
 * - challenge
 * - payload_len
 * - payload[payload_len bytes only]
 *
 * Parameters:
 *   cfg  - Pointer to the loaded siglatch_config containing user public keys.
 *   pkt  - Pointer to the KnockPacket received (already decrypted and parsed).
 *
 * Returns:
 *   1 on successful signature verification (packet is authentic),
 *   0 on failure (signature mismatch or validation error).
 *
 * Important:
 *   - The server must have the user's public key preloaded into cfg->users[].pubkey.
 *   - The packet fields must not be modified after signing.
 *   - Only the first 32 bytes of the signature are verified (matching compact SHA-256 digest signing).
 *   - Replay protection should be handled separately (this function only authenticates integrity).
 */

int validateSignature(const SiglatchOpenSSLSession *session, const KnockPacket *pkt) {
    if (!session || !pkt) {
        LOGE("[validateSignature] ❌ Null session or packet\n");
        return 0;
    }

    // 1. Generate SHA256 digest over structured fields
    uint8_t digest[32] = {0};
    if (!lib.payload_digest.generate(pkt, digest)) {
        LOGE("[validateSignature] ❌ Failed to generate digest\n");
        return 0;
    }

    dumpDigest("Server-computed Digest", digest, sizeof(digest));
    dumpDigest("Packet hmac field (Client-sent Signature)", pkt->hmac, sizeof(pkt->hmac));

    // 2. Validate HMAC signature using session HMAC key
    if (!lib.payload_digest.validate(session->hmac_key, digest, pkt->hmac)) {
        LOGW("[validateSignature] ❌ Signature mismatch for user_id %u\n", pkt->user_id);
        return 0;
    }

    LOGT("[validateSignature] ✅ Signature verified for user_id %u\n", pkt->user_id);
    return 1;
}

const siglatch_user *find_user_by_id(const siglatch_config *cfg, uint32_t user_id) {
    if (!cfg) return NULL;

    for (int i = 0; i < cfg->user_count; ++i) {
        const siglatch_user *u = &cfg->users[i];
        if (u->enabled && u->id == user_id) {
            return u;
        }
    }

    return NULL;  // Not found
}

