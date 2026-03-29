/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "detect.h"

#include <time.h>
#include <string.h>

#include "codec3/v1/v1_packet.h"
#include "codec3/v2/v2_form1.h"

#define SHARED_KNOCK_DETECT_V1_TIMESTAMP_FUZZ 300

static uint32_t shared_knock_detect_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static int shared_knock_detect_v1_unpack(const uint8_t *buf,
                                         size_t buflen,
                                         SharedKnockCodec3V1Packet *pkt) {
  if (!buf || !pkt) {
    return 0;
  }

  if (buflen < SHARED_KNOCK_CODEC3_V1_PACKET_SIZE) {
    return 0;
  }

  memcpy(pkt, buf, sizeof(*pkt));
  return 1;
}

static int shared_knock_detect_v1_validate(const SharedKnockCodec3V1Packet *pkt) {
  time_t now = 0;

  if (!pkt) {
    return 0;
  }

  if (pkt->version != SHARED_KNOCK_CODEC3_V1_VERSION) {
    return 0;
  }

  if (pkt->payload_len > sizeof(pkt->payload)) {
    return 0;
  }

  now = time(NULL);
  if (pkt->timestamp > now + SHARED_KNOCK_DETECT_V1_TIMESTAMP_FUZZ ||
      pkt->timestamp < now - SHARED_KNOCK_DETECT_V1_TIMESTAMP_FUZZ) {
    return 0;
  }

  return 1;
}

static int shared_knock_detect_v1_deserialize(const uint8_t *buf,
                                              size_t buflen,
                                              SharedKnockCodec3V1Packet *pkt) {
  if (!shared_knock_detect_v1_unpack(buf, buflen, pkt)) {
    return 0;
  }

  return shared_knock_detect_v1_validate(pkt);
}

int shared_knock_detect_init(void) {
  return 1;
}

void shared_knock_detect_shutdown(void) {
}

int shared_knock_detect(const uint8_t *buf, size_t buflen, SharedKnockRoutingInfo *out) {
  SharedKnockCodec3V1Packet pkt_v1 = {0};
  uint32_t magic = 0;
  uint32_t version = 0;
  uint8_t form = 0;

  if (!buf || !out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));

  if (buflen >= SHARED_KNOCK_CODEC3_V2_FORM1_OUTER_SIZE) {
    magic = shared_knock_detect_read_u32_be(buf + 0);
    version = shared_knock_detect_read_u32_be(buf + 4);
    form = buf[8];

    if (magic == SHARED_KNOCK_CODEC3_FAMILY_MAGIC &&
        version == SHARED_KNOCK_CODEC3_V2_WIRE_VERSION &&
        form == SHARED_KNOCK_CODEC3_FORM1_ID) {
      out->kind = SHARED_KNOCK_ROUTE_V2_FORM1;
      out->version = version;
      out->form = form;
      out->expected_packet_size = SHARED_KNOCK_CODEC3_V2_FORM1_PACKET_SIZE;
      out->exact_size_required = 1;
      out->identified_by_prefix = 1;
      return 1;
    }
  }

  if (buflen == SHARED_KNOCK_CODEC3_V1_PACKET_SIZE &&
      shared_knock_detect_v1_deserialize(buf, buflen, &pkt_v1)) {
    out->kind = SHARED_KNOCK_ROUTE_V1_LEGACY;
    out->version = pkt_v1.version;
    out->form = 0;
    out->expected_packet_size = SHARED_KNOCK_CODEC3_V1_PACKET_SIZE;
    out->exact_size_required = 1;
    out->identified_by_prefix = 0;
    return 1;
  }

  return 0;
}

SharedKnockRouteKind shared_knock_detect_kind(const uint8_t *buf, size_t buflen) {
  SharedKnockRoutingInfo info = {0};

  if (!shared_knock_detect(buf, buflen, &info)) {
    return SHARED_KNOCK_ROUTE_UNKNOWN;
  }

  return info.kind;
}

const char *shared_knock_detect_kind_name(SharedKnockRouteKind kind) {
  switch (kind) {
  case SHARED_KNOCK_ROUTE_V1_LEGACY:
    return "v1-legacy";
  case SHARED_KNOCK_ROUTE_V2_FORM1:
    return "v2-form1";
  case SHARED_KNOCK_ROUTE_UNKNOWN:
  default:
    return "unknown";
  }
}

static const SharedKnockDetectLib shared_knock_detect_lib = {
  .init = shared_knock_detect_init,
  .shutdown = shared_knock_detect_shutdown,
  .detect_kind = shared_knock_detect_kind,
  .detect = shared_knock_detect,
  .kind_name = shared_knock_detect_kind_name
};

const SharedKnockDetectLib *get_shared_knock_detect_lib(void) {
  return &shared_knock_detect_lib;
}
