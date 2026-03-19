/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "detect.h"

#include <string.h>

#include "v1_codec.h"
#include "v2_form1.h"

static uint32_t shared_knock_detect_read_u32_be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

int shared_knock_detect_init(void) {
  return 1;
}

void shared_knock_detect_shutdown(void) {
}

int shared_knock_detect(const uint8_t *buf, size_t buflen, SharedKnockRoutingInfo *out) {
  KnockPacketV1 pkt_v1 = {0};
  uint32_t magic = 0;
  uint32_t version = 0;
  uint8_t form = 0;

  if (!buf || !out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));

  if (buflen >= SHARED_KNOCK_V2_FORM1_OUTER_SIZE) {
    magic = shared_knock_detect_read_u32_be(buf + 0);
    version = shared_knock_detect_read_u32_be(buf + 4);
    form = buf[8];

    if (magic == SHARED_KNOCK_FAMILY_MAGIC &&
        version == SHARED_KNOCK_V2_WIRE_VERSION &&
        form == SHARED_KNOCK_FORM1_ID) {
      out->kind = SHARED_KNOCK_ROUTE_V2_FORM1;
      out->version = version;
      out->form = form;
      out->expected_packet_size = SHARED_KNOCK_V2_FORM1_PACKET_SIZE;
      out->exact_size_required = 1;
      out->identified_by_prefix = 1;
      return 1;
    }
  }

  if (buflen == SHARED_KNOCK_V1_PACKET_SIZE &&
      shared_knock_v1_codec_deserialize(buf, buflen, &pkt_v1) == SL_PAYLOAD_OK) {
    out->kind = SHARED_KNOCK_ROUTE_V1_LEGACY;
    out->version = pkt_v1.version;
    out->form = 0;
    out->expected_packet_size = SHARED_KNOCK_V1_PACKET_SIZE;
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
