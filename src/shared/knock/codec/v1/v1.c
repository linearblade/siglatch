/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "v1.h"

#include <string.h>
#include <time.h>

#define SHARED_KNOCK_V1_TIMESTAMP_FUZZ 300

int shared_knock_v1_codec_init(void) {
  return 1;
}

void shared_knock_v1_codec_shutdown(void) {
}

int shared_knock_v1_codec_pack(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen) {
  if (!pkt || !out_buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (maxlen < sizeof(KnockPacket)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(out_buf, pkt, sizeof(KnockPacket));
  return (int)sizeof(KnockPacket);
}

int shared_knock_v1_codec_unpack(const uint8_t *buf, size_t buflen, KnockPacket *pkt) {
  if (!pkt || !buf) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  if (buflen < sizeof(KnockPacket)) {
    return SL_PAYLOAD_ERR_UNPACK;
  }

  memcpy(pkt, buf, sizeof(KnockPacket));
  return SL_PAYLOAD_OK;
}

int shared_knock_v1_codec_validate(const KnockPacket *pkt) {
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

int shared_knock_v1_codec_deserialize(const uint8_t *buf, size_t buflen, KnockPacket *pkt) {
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

int shared_knock_v1_codec_normalize(const uint8_t *buf,
                                    size_t buflen,
                                    const char *ip,
                                    uint16_t client_port,
                                    int encrypted,
                                    SharedKnockNormalizedUnit *out) {
  KnockPacket pkt = {0};
  int deserialize_rc = 0;
  size_t payload_len = 0;
  size_t ip_len = 0;
  size_t copy_len = 0;
  int overflow = 0;

  if (!out) {
    return SL_PAYLOAD_ERR_NULL_PTR;
  }

  deserialize_rc = shared_knock_v1_codec_deserialize(buf, buflen, &pkt);
  if (deserialize_rc != SL_PAYLOAD_OK) {
    return deserialize_rc;
  }

  overflow = (pkt.payload_len > sizeof(out->payload));

  memset(out, 0, sizeof(*out));

  out->complete = 1;
  out->wire_version = pkt.version;
  out->wire_form = 0u;
  out->session_id = 0;
  out->message_id = 0;
  out->stream_id = 0;
  out->fragment_index = 0;
  out->fragment_count = 1;
  out->timestamp = pkt.timestamp;
  out->user_id = pkt.user_id;
  out->action_id = pkt.action_id;
  out->challenge = pkt.challenge;
  memcpy(out->hmac, pkt.hmac, sizeof(out->hmac));

  if (ip) {
    ip_len = strlen(ip);
    if (ip_len >= sizeof(out->ip)) {
      ip_len = sizeof(out->ip) - 1u;
    }
    memcpy(out->ip, ip, ip_len);
    out->ip[ip_len] = '\0';
  }

  out->client_port = client_port;
  out->encrypted = encrypted ? 1 : 0;
  copy_len = pkt.payload_len;
  if (copy_len > sizeof(out->payload)) {
    copy_len = sizeof(out->payload);
  }

  out->payload_len = copy_len;
  payload_len = copy_len;
  if (payload_len > 0) {
    memcpy(out->payload, pkt.payload, payload_len);
  }

  return overflow ? SL_PAYLOAD_ERR_OVERFLOW : SL_PAYLOAD_OK;
}

const char *shared_knock_v1_codec_deserialize_strerror(int code) {
  switch (code) {
  case SL_PAYLOAD_OK:
    return "No error";
  case SL_PAYLOAD_ERR_NULL_PTR:
    return "KnockPacket pointer is null";
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
  .normalize = shared_knock_v1_codec_normalize,
  .deserialize_strerror = shared_knock_v1_codec_deserialize_strerror
};

const SharedKnockV1CodecLib *get_shared_knock_v1_codec_lib(void) {
  return &shared_knock_v1_codec;
}
