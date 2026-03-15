/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "codec.h"

#include <string.h>
#include <time.h>

#define SHARED_KNOCK_EXPECTED_VERSION 1
#define SHARED_KNOCK_TIMESTAMP_FUZZ 300

int shared_knock_codec_init(void) {
  return 1;
}

void shared_knock_codec_shutdown(void) {
}

int shared_knock_codec_pack(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen) {
  if (!pkt || !out_buf) {
    return -1;
  }

  if (maxlen < sizeof(KnockPacket)) {
    return -2;
  }

  memcpy(out_buf, pkt, sizeof(KnockPacket));
  return (int)sizeof(KnockPacket);
}

int shared_knock_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacket *pkt) {
  if (!pkt || !buf) {
    return -1;
  }

  if (buflen < sizeof(KnockPacket)) {
    return -2;
  }

  memcpy(pkt, buf, sizeof(KnockPacket));
  return 0;
}

int shared_knock_codec_validate(const KnockPacket *pkt) {
  time_t now = 0;

  if (!pkt) {
    return -1;
  }

  if (pkt->version != SHARED_KNOCK_EXPECTED_VERSION) {
    return -2;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return -4;
  }

  now = time(NULL);
  if (pkt->timestamp > now + SHARED_KNOCK_TIMESTAMP_FUZZ ||
      pkt->timestamp < now - SHARED_KNOCK_TIMESTAMP_FUZZ) {
    return -3;
  }

  return 0;
}

int shared_knock_codec_deserialize(
    const uint8_t *decrypted_buffer,
    size_t decrypted_len,
    KnockPacket *pkt) {
  int validate_rc = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (shared_knock_codec_unpack(decrypted_buffer, decrypted_len, pkt) != 0) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  validate_rc = shared_knock_codec_validate(pkt);
  if (validate_rc == -4) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  if (validate_rc != 0) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

const char *shared_knock_codec_deserialize_strerror(int code) {
  switch (code) {
  case SL_PAYLOAD_OK:
    return "No error";
  case SL_PAYLOAD_ERR_NULL_PTR:
    return "KnockPacket pointer is null";
  case SL_PAYLOAD_ERR_UNPACK:
    return "Failed to unpack knock payload";
  case SL_PAYLOAD_ERR_VALIDATE:
    return "Knock packet validation failed";
  case SL_PAYLOAD_ERR_OVERFLOW:
    return "Knock payload_len exceeds payload buffer";
  default:
    return "Unknown payload error";
  }
}

static const SharedKnockCodecLib shared_knock_codec = {
  .init = shared_knock_codec_init,
  .shutdown = shared_knock_codec_shutdown,
  .pack = shared_knock_codec_pack,
  .unpack = shared_knock_codec_unpack,
  .validate = shared_knock_codec_validate,
  .deserialize = shared_knock_codec_deserialize,
  .deserialize_strerror = shared_knock_codec_deserialize_strerror
};

const SharedKnockCodecLib *get_shared_knock_codec_lib(void) {
  return &shared_knock_codec;
}
