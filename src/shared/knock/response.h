/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_RESPONSE_H
#define SIGLATCH_SHARED_KNOCK_RESPONSE_H

#include <stdint.h>

/*
 * v1 response packets reuse KnockPacket and reserve action_id = 0.
 *
 * Response payload layout:
 *   byte 0: status
 *   byte 1: original request action id
 *   byte 2: flags
 *   byte 3..n: response text bytes (not NUL-terminated on wire)
 */

#define SL_KNOCK_RESPONSE_ACTION_ID 0

#define SL_KNOCK_RESPONSE_STATUS_OK    1
#define SL_KNOCK_RESPONSE_STATUS_ERROR 2

#define SL_KNOCK_RESPONSE_FLAG_TRUNCATED 0x01

#define SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE 3

typedef struct __attribute__((packed)) {
  uint8_t status;
  uint8_t request_action_id;
  uint8_t flags;
} KnockResponseV1Header;

#endif
