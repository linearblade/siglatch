/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "helper.h"

#include <stdio.h>
#include <string.h>

#include "../../../shared/shared.h"
#include "../../../stdlib/utils.h"
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

int structurePacket(KnockPacket *pkt_out, const uint8_t *payload, size_t len,
                    uint16_t user_id, uint8_t action_id) {
    if (!pkt_out || !payload) {
        lib.log.console("structurePacket: Invalid input.\n");
        return 0;
    }

    memset(pkt_out, 0, sizeof(KnockPacket));

    pkt_out->version = 1;
    pkt_out->timestamp = (uint32_t)lib.time.unix_ts();
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

int signPacket(SiglatchOpenSSLSession *session, KnockPacket *pkt) {
    if (!session || !pkt) {
        return 0;
    }

    uint8_t digest[32] = {0};

    if (!shared.knock.digest.generate(pkt, digest)) {
      lib.log.console("Failed to generate digest in signPacket()\n");
      return 0;
    }

    dumpDigest("Client-computed Digest", digest, sizeof(digest));

    if (!lib.openssl.sign(session, digest, pkt->hmac)) {
      lib.log.console("Failed to sign digest in signPacket()\n");
      return 0;
    }

    return 1;
}

int signWrapper(const Opts *opts, SiglatchOpenSSLSession *session, KnockPacket *pkt) {
  switch (opts->hmac_mode) {
    case HMAC_MODE_NORMAL:
      if (!signPacket(session, pkt)) {
        LOGE("Failed to sign packet");
        return 0;
      }
      break;

    case HMAC_MODE_DUMMY:
      memset(pkt->hmac, 0x42, sizeof(pkt->hmac));
      LOGD("Using dummy HMAC (0x42 padded)\n");
      break;

    case HMAC_MODE_NONE:
      memset(pkt->hmac, 0, sizeof(pkt->hmac));
      LOGD("HMAC signing disabled\n");
      break;

    default:
      LOGE("Unknown HMAC mode: %d", opts->hmac_mode);
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

int structureOrDeadDrop(const Opts *opts, const KnockPacket *pkt,
                        uint8_t *packed, int *packed_len) {
  if (opts->dead_drop) {
    if (opts->payload_len == 0) {
      LOGE("Dead drop mode requires non-empty payload\n");
      return 0;
    }

    memcpy(packed, opts->payload, opts->payload_len);
    *packed_len = (int)opts->payload_len;

    LOGD("Prepared dead-drop payload (%d bytes)", *packed_len);
  } else {
    int len = shared.knock.codec.pack(pkt, packed, 512);
    if (len <= 0) {
      LOGE("Failed to pack structured payload\n");
      return 0;
    }

    *packed_len = len;
    LOGD("Packed structured KnockPacket (%d bytes)", len);
  }

  return 1;
}
