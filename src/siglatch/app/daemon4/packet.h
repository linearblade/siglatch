/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_PACKET_H
#define SIGLATCH_SERVER_APP_DAEMON4_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "../payload/reply.h"

/*
 * App-owned semantic packet shape for daemon4.
 *
 * This is intentionally separate from the m7mux2 transport envelope so the
 * codec layer can include one daemon4 header and work against the same request
 * data the job pipeline owns.
 */
typedef struct AppDaemon4RequestPacket {
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint8_t *payload_buffer;
  size_t payload_len;
  size_t payload_cap;
} AppDaemon4RequestPacket;

typedef AppDaemon4RequestPacket AppDaemon4UserData;
typedef AppActionReply AppDaemon4ReplyPacket;

#endif /* SIGLATCH_SERVER_APP_DAEMON4_PACKET_H */
