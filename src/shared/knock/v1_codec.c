/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v1_codec.h"

#include <string.h>
#include <time.h>

#define SHARED_KNOCK_V1_TIMESTAMP_FUZZ 300

int shared_knock_v1_codec_init(void) {
  return 1;
}

void shared_knock_v1_codec_shutdown(void) {
}

int shared_knock_v1_codec_pack(const KnockPacketV1 *pkt, uint8_t *out_buf, size_t maxlen) {
  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (maxlen < sizeof(KnockPacketV1)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(out_buf, pkt, sizeof(KnockPacketV1));
  return (int)sizeof(KnockPacketV1);
}

int shared_knock_v1_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt) {
  if (!pkt || !buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen < sizeof(KnockPacketV1)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(pkt, buf, sizeof(KnockPacketV1));
  return SL_PAYLOAD_OK;
}

int shared_knock_v1_codec_validate(const KnockPacketV1 *pkt) {
  time_t now = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->version != SHARED_KNOCK_V1_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  now = time(NULL);
  if (pkt->timestamp > now + SHARED_KNOCK_V1_TIMESTAMP_FUZZ ||
      pkt->timestamp < now - SHARED_KNOCK_V1_TIMESTAMP_FUZZ) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

int shared_knock_v1_codec_deserialize(const uint8_t *buf, size_t buflen, KnockPacketV1 *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_v1_codec_unpack(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_v1_codec_validate(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

const char *shared_knock_v1_codec_deserialize_strerror(int code) {
  switch (code) {
  case SL_PAYLOAD_OK:
    return "No error";
  case SL_PAYLOAD_ERR_NULL_PTR:
    return "KnockPacketV1 pointer is null";
  case SL_PAYLOAD_ERR_UNPACK:
    return "Failed to unpack v1 knock payload";
  case SL_PAYLOAD_ERR_VALIDATE:
    return "V1 knock packet validation failed";
  case SL_PAYLOAD_ERR_OVERFLOW:
    return "V1 knock payload_len exceeds payload buffer";
  default:
    return "Unknown payload error";
  }
}

static const SharedKnockV1CodecLib shared_knock_v1_codec = {
  .init = shared_knock_v1_codec_init,
  .shutdown = shared_knock_v1_codec_shutdown,
  .pack = shared_knock_v1_codec_pack,
  .unpack = shared_knock_v1_codec_unpack,
  .validate = shared_knock_v1_codec_validate,
  .deserialize = shared_knock_v1_codec_deserialize,
  .deserialize_strerror = shared_knock_v1_codec_deserialize_strerror
};

const SharedKnockV1CodecLib *get_shared_knock_v1_codec_lib(void) {
  return &shared_knock_v1_codec;
}
