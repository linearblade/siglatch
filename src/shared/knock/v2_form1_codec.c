/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v2_form1_codec.h"

#include <string.h>
#include <time.h>

#define SHARED_KNOCK_V2_FORM1_TIMESTAMP_FUZZ 300

static uint16_t shared_knock_v2_read_u16_be(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static uint32_t shared_knock_v2_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static void shared_knock_v2_write_u16_be(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((value >> 8) & 0xFFu);
  dst[1] = (uint8_t)(value & 0xFFu);
}

static void shared_knock_v2_write_u32_be(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)((value >> 24) & 0xFFu);
  dst[1] = (uint8_t)((value >> 16) & 0xFFu);
  dst[2] = (uint8_t)((value >> 8) & 0xFFu);
  dst[3] = (uint8_t)(value & 0xFFu);
}

int shared_knock_v2_form1_codec_init(void) {
  return 1;
}

void shared_knock_v2_form1_codec_shutdown(void) {
}

int shared_knock_v2_form1_codec_pack(const KnockPacketV2Form1 *pkt, uint8_t *out_buf, size_t maxlen) {
  size_t payload_len = 0;

  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (maxlen < SHARED_KNOCK_V2_FORM1_PACKET_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  if (shared_knock_v2_form1_codec_validate(pkt) != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  payload_len = pkt->inner.payload_len;
  memset(out_buf, 0, SHARED_KNOCK_V2_FORM1_PACKET_SIZE);

  shared_knock_v2_write_u32_be(out_buf + 0, pkt->outer.magic);
  shared_knock_v2_write_u32_be(out_buf + 4, pkt->outer.version);
  out_buf[8] = pkt->outer.form;

  shared_knock_v2_write_u32_be(out_buf + 9, pkt->inner.timestamp);
  shared_knock_v2_write_u16_be(out_buf + 13, pkt->inner.user_id);
  out_buf[15] = pkt->inner.action_id;
  shared_knock_v2_write_u32_be(out_buf + 16, pkt->inner.challenge);
  memcpy(out_buf + 20, pkt->inner.hmac, sizeof(pkt->inner.hmac));
  shared_knock_v2_write_u16_be(out_buf + 52, pkt->inner.payload_len);

  if (payload_len > 0) {
    memcpy(out_buf + SHARED_KNOCK_V2_FORM1_OUTER_SIZE + SHARED_KNOCK_V2_FORM1_INNER_SIZE,
           pkt->payload,
           payload_len);
  }

  return (int)SHARED_KNOCK_V2_FORM1_PACKET_SIZE;
}

int shared_knock_v2_form1_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacketV2Form1 *pkt) {
  if (!buf || !pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen != SHARED_KNOCK_V2_FORM1_PACKET_SIZE) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memset(pkt, 0, sizeof(*pkt));

  pkt->outer.magic = shared_knock_v2_read_u32_be(buf + 0);
  pkt->outer.version = shared_knock_v2_read_u32_be(buf + 4);
  pkt->outer.form = buf[8];

  pkt->inner.timestamp = shared_knock_v2_read_u32_be(buf + 9);
  pkt->inner.user_id = shared_knock_v2_read_u16_be(buf + 13);
  pkt->inner.action_id = buf[15];
  pkt->inner.challenge = shared_knock_v2_read_u32_be(buf + 16);
  memcpy(pkt->inner.hmac, buf + 20, sizeof(pkt->inner.hmac));
  pkt->inner.payload_len = shared_knock_v2_read_u16_be(buf + 52);

  memcpy(pkt->payload,
         buf + SHARED_KNOCK_V2_FORM1_OUTER_SIZE + SHARED_KNOCK_V2_FORM1_INNER_SIZE,
         sizeof(pkt->payload));

  return SL_PAYLOAD_OK;
}

int shared_knock_v2_form1_codec_validate(const KnockPacketV2Form1 *pkt) {
  time_t now = 0;

  if (!pkt) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (pkt->outer.magic != SHARED_KNOCK_FAMILY_MAGIC) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.version != SHARED_KNOCK_V2_WIRE_VERSION) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->outer.form != SHARED_KNOCK_FORM1_ID) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  if (pkt->inner.payload_len > sizeof(pkt->payload)) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }

  now = time(NULL);
  if (pkt->inner.timestamp > now + SHARED_KNOCK_V2_FORM1_TIMESTAMP_FUZZ ||
      pkt->inner.timestamp < now - SHARED_KNOCK_V2_FORM1_TIMESTAMP_FUZZ) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

int shared_knock_v2_form1_codec_deserialize(const uint8_t *buf,
                                            size_t buflen,
                                            KnockPacketV2Form1 *pkt) {
  int validate_rc = 0;

  validate_rc = shared_knock_v2_form1_codec_unpack(buf, buflen, pkt);
  if (validate_rc != SL_PAYLOAD_OK) {
    return validate_rc;
  }

  validate_rc = shared_knock_v2_form1_codec_validate(pkt);
  if (validate_rc == SL_PAYLOAD_ERR_OVERFLOW) {
    return SL_PAYLOAD_ERR_OVERFLOW;
  }
  if (validate_rc != SL_PAYLOAD_OK) {
    return SL_PAYLOAD_ERR_VALIDATE;
  }

  return SL_PAYLOAD_OK;
}

const char *shared_knock_v2_form1_codec_deserialize_strerror(int code) {
  switch (code) {
  case SL_PAYLOAD_OK:
    return "No error";
  case SL_PAYLOAD_ERR_NULL_PTR:
    return "KnockPacketV2Form1 pointer is null";
  case SL_PAYLOAD_ERR_UNPACK:
    return "Failed to unpack v2.form1 knock payload";
  case SL_PAYLOAD_ERR_VALIDATE:
    return "V2.form1 knock packet validation failed";
  case SL_PAYLOAD_ERR_OVERFLOW:
    return "V2.form1 payload_len exceeds payload buffer";
  default:
    return "Unknown payload error";
  }
}

static const SharedKnockV2Form1CodecLib shared_knock_v2_form1_codec = {
  .init = shared_knock_v2_form1_codec_init,
  .shutdown = shared_knock_v2_form1_codec_shutdown,
  .pack = shared_knock_v2_form1_codec_pack,
  .unpack = shared_knock_v2_form1_codec_unpack,
  .validate = shared_knock_v2_form1_codec_validate,
  .deserialize = shared_knock_v2_form1_codec_deserialize,
  .deserialize_strerror = shared_knock_v2_form1_codec_deserialize_strerror
};

const SharedKnockV2Form1CodecLib *get_shared_knock_v2_form1_codec_lib(void) {
  return &shared_knock_v2_form1_codec;
}
