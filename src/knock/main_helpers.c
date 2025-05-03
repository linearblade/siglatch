/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "main_helpers.h"
#include "../stdlib/utils.h" // my temporary trash bin for shit that goes to relevant places later.
#include "lib.h"


int init_user_openssl_session(const Opts *opts, SiglatchOpenSSLSession *session) {
    if (!session ) {
        lib.log.console("❌ NULL pointer passed to OpenSSL session initializer\n");
        return 0;
    }
    if (!opts ) {
        lib.log.console("❌ NULL configuration pointer passed\n");
        return 0;
    }

    if (!lib.openssl.session_init(session)) {
        lib.log.console("❌ Failed to initialize OpenSSL session!\n");
        return 0;
    }

    if (!lib.openssl.session_readHMAC(session, opts->hmac_key_path)) {
        lib.log.console("❌ Failed to load HMAC key!\n");
        return 0;
    }

    if (!lib.openssl.session_readPublicKey(session, opts->server_pubkey_path)) {
        lib.log.console("❌ Failed to load public key!\n");
        return 0;
    }

    return 1;
}

// Clean helper to create and pack a KnockPacket
int structurePacket(KnockPacket *pkt_out, const uint8_t *payload, size_t len,  uint16_t user_id, uint8_t action_id) {
    if (!pkt_out || !payload) {
        lib.log.console("❌ structurePacket: Invalid input.\n");
        return 0;
    }

    memset(pkt_out, 0, sizeof(KnockPacket));

    pkt_out->version = 1;
    pkt_out->timestamp = (uint32_t)lib.time.unix();
    pkt_out->user_id = user_id;
    pkt_out->action_id = action_id;
    pkt_out->challenge = lib.random.challenge();

    // Clamp to max length
    if (len > sizeof(pkt_out->payload)) {
        len = sizeof(pkt_out->payload);
    }

    memcpy(pkt_out->payload, payload, len);
    pkt_out->payload_len = (uint16_t)len;

    return 1;
}
/*
int structurePacket(KnockPacket *pkt_out, const char *payload_data, uint16_t user_id, uint8_t action_id, int is_text) {
    if (!pkt_out || !payload_data) {
        lib.log.console("❌ structurePacket: Invalid input.\n");
        return 0;
    }

    // Zero out the packet
    memset(pkt_out, 0, sizeof(KnockPacket));

    pkt_out->version = 1;
    pkt_out->timestamp = (uint32_t)lib.time.unix();
    pkt_out->user_id = user_id;
    pkt_out->action_id = action_id;
    // 🧂 (adding nonce -- replay protection)
    pkt_out->challenge = lib.random.challenge();

    // Calculate message length safely
    size_t msg_len = strlen(payload_data);
    if (msg_len >= sizeof(pkt_out->payload)) {
        msg_len = sizeof(pkt_out->payload) - 1; // Leave room for optional null
    }

    // Copy the payload
    memcpy(pkt_out->payload, payload_data, msg_len);

    // Optionally null-terminate (text-mode)
    if (is_text) {
        pkt_out->payload[msg_len] = '\0';
    }

    // Set real payload length
    pkt_out->payload_len = (uint16_t)msg_len;

    return 1; // Success
    }*/

/**
 * signPacket - Sign a KnockPacket using the client's private key.
 *
 * This function computes a SHA-256 digest over the critical fields of the KnockPacket,
 * and then signs that digest using the provided private key (EVP_PKEY).
 *
 * The resulting compact signature is stored directly into the packet's hmac[32] field.
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
 *   pkt      - Pointer to the KnockPacket to be signed (must be filled first).
 *   pkey     - Pointer to the loaded EVP_PKEY (client's private key).
 *
 * Returns:
 *   1 on success (signature generated and stored in pkt->hmac),
 *   0 on failure (error during hashing or signing).
 */

/**
 * signPacket - Sign a KnockPacket using the client's private key.
 *
 * Signs the manually computed SHA-256 digest of packet fields
 * directly using EVP_PKEY_sign(), without rehashing.
 *
 * Stores the first 32 bytes of the full signature into pkt->hmac.
 */

int signPacket(SiglatchOpenSSLSession *session, KnockPacket *pkt) {
    if (!session || !pkt) {
        return 0;
    }

    uint8_t digest[32] = {0};

    if (!lib.payload_digest.generate(pkt, digest)) {
      lib.log.console("❌ Failed to generate digest in signPacket()\n");
      return 0;
    }
    

    dumpDigest("Client-computed Digest", digest, sizeof(digest));


    if (!lib.openssl.sign(session, digest, pkt->hmac)) {
      lib.log.console("❌ Failed to sign digest in signPacket()\n");
      return 0;
    }
    

    return 1;
}

//see .h for docu
int signWrapper(const Opts *opts, SiglatchOpenSSLSession *session, KnockPacket *pkt) {
  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!signPacket(session, pkt)) {
        LOGE("Failed to sign packet");
        return 0;
      }
      break;

    case HMAC_MODE_DUMMY:
      memset(pkt->hmac, 0x42, sizeof(pkt->hmac));  // Arbitrary dummy signature
      LOGD("🧪 Using dummy HMAC (0x42 padded)\n");
      break;

    case HMAC_MODE_NONE:
      memset(pkt->hmac, 0, sizeof(pkt->hmac));  // Zero signature
      LOGD("🚫 HMAC signing disabled\n");
      break;

    default:
      LOGE("Unknown HMAC mode: %d", opts->hmac_mode);
      return 0;
  }

  return 1;
}


 int encryptWrapper(const Opts *opts, SiglatchOpenSSLSession *session,
                          const uint8_t *input, size_t input_len,
                          unsigned char *out_buf, size_t *out_len)
{
  if (opts->encrypt) {
    if (!lib.openssl.session_encrypt(session, input, input_len, out_buf, out_len)) {
      LOGE("OpenSSL encryption failed\n");
      return 0;
    }
    LOGD("🔐 Encrypted payload (%zu bytes)\n", *out_len);
  } else {
    memcpy(out_buf, input, input_len);
    *out_len = input_len;
    LOGD("📤 Sending raw payload (unencrypted, %zu bytes)\n", input_len);
  }

  return 1;
}


int structureOrDeadDrop(const Opts *opts, const KnockPacket *pkt,
                               uint8_t *packed, int *packed_len) {
  if (opts->dead_drop) {
    if (opts->payload_len == 0) {
      LOGE("Dead drop mode requires non-empty payload\n");
      return 0;
    }

    memcpy(packed, opts->payload, opts->payload_len);
    *packed_len = (int)opts->payload_len;

    LOGD("📦 Prepared dead-drop payload (%d bytes)", *packed_len);
  } else {
    int len = lib.payload.pack(pkt, packed, 512);
    if (len <= 0) {
      LOGE("Failed to pack structured payload\n");
      return 0;
    }

    *packed_len = len;
    LOGD("📦 Packed structured KnockPacket (%d bytes)", len);
  }

  return 1;
}
