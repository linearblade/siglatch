/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "payload.h"
#include <string.h>
#include <time.h>

#define EXPECTED_VERSION 1
#define TIMESTAMP_FUZZ 300  // ±5 minutes window for freshness

// ── Internal implementations ──────────────────────

void payload_init(void) {
    // Placeholder: no state yet
    // If we later load dynamic field mappings, they go here
}

void payload_shutdown(void) {
    // Placeholder: no teardown needed
}

static int pack_knock(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen) {
  if (!pkt || !out_buf) return -1;
  if (maxlen < sizeof(KnockPacket)) return -2;

  memcpy(out_buf, pkt, sizeof(KnockPacket));
  return (int)sizeof(KnockPacket);
}

static int unpack_knock(const uint8_t *buf, size_t buflen, KnockPacket *pkt) {
  if (!pkt || !buf) return -1;
  if (buflen < sizeof(KnockPacket)) return -2;

  memcpy(pkt, buf, sizeof(KnockPacket));
  return 0;
}

static int validate_knock(const KnockPacket *pkt) {
  if (!pkt) return -1;

  if (pkt->version != EXPECTED_VERSION) {
    return -2; // wrong version
  }

  time_t now = time(NULL);
  if (pkt->timestamp > now + TIMESTAMP_FUZZ ||
      pkt->timestamp < now - TIMESTAMP_FUZZ) {
    return -3; // expired or invalid timestamp
  }

  // could add more checks: nonzero user_id, action_id range, etc

  return 0;  // valid
}

static int deserialize(const uint8_t *decrypted_buffer, size_t decrypted_len, KnockPacket *pkt) {
    if (!pkt) {
        return SL_PAYLOAD_ERR_NULL_PTR;
    }

    if (unpack_knock(decrypted_buffer, decrypted_len, pkt) != 0) {
        return SL_PAYLOAD_ERR_UNPACK;
    }

    if (validate_knock(pkt) != 0) {
        return SL_PAYLOAD_ERR_VALIDATE;
    }

    return SL_PAYLOAD_OK;
}
static const char *deserialize_strerror(int code) {
    switch (code) {
        case SL_PAYLOAD_OK:              return "No error";
        case SL_PAYLOAD_ERR_NULL_PTR:    return "KnockPacket pointer is null";
        case SL_PAYLOAD_ERR_UNPACK:      return "Failed to unpack knock payload";
        case SL_PAYLOAD_ERR_VALIDATE:    return "Knock packet validation failed";
        default:                         return "Unknown payload error";
    }
}

// ── Singleton interface ───────────────────────────

static const Payload payload = {
  .init                 = payload_init,
  .shutdown             = payload_shutdown,
  .pack                 = pack_knock,
  .unpack               = unpack_knock,
  .validate             = validate_knock,
  .deserialize          = deserialize,
  .deserialize_strerror = deserialize_strerror
};

const Payload *get_payload_lib(void) {
  return &payload;
}
