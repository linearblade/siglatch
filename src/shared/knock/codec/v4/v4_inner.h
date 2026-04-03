/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_V4_INNER_H
#define SIGLATCH_SHARED_KNOCK_CODEC_V4_INNER_H

#include <stdint.h>

/* Serialized wire size for the inert Siglatch v4 inner envelope. */
#define SIGLATCH_V4_INNER_ENVELOPE_WIRE_SIZE 30u

/* Implemented but inert for now; this is Siglatch-specific, not a mux protocol. */
typedef struct SiglatchV4InnerEnvelope {
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint8_t flags;
  uint8_t stream_type;
} SiglatchV4InnerEnvelope;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_V4_INNER_H */
