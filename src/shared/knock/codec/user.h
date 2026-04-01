/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC_USER_H
#define SIGLATCH_SHARED_KNOCK_CODEC_USER_H

#include <stdint.h>

/*
 * Shared codec-facing user data contract.
 *
 * This intentionally duplicates the current flat knock packet layout for now,
 * but keeps send/recv named separately so the app-side contract can diverge
 * later without touching m7mux.
 */

#define M7MUX_USER_DATA_VERSION 1u
#define M7MUX_USER_DATA_PAYLOAD_MAX 199u

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
  uint8_t payload[M7MUX_USER_DATA_PAYLOAD_MAX];
} M7MuxUserSendData;

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint16_t payload_len;
  uint8_t payload[M7MUX_USER_DATA_PAYLOAD_MAX];
} M7MuxUserRecvData;

#endif /* SIGLATCH_SHARED_KNOCK_CODEC_USER_H */
