/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

// payload.h

#ifndef SIGLATCH_PAYLOAD_H
#define SIGLATCH_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>
typedef struct __attribute__((packed)) {
    uint8_t  version;        // Packet format version
    uint32_t timestamp;      // Time when the packet was created
    uint16_t user_id;        // User ID who sent the packet
    uint8_t  action_id;      // Action requested
    uint32_t challenge;      // Anti-replay random value
    uint8_t  hmac[32];       // HMAC for integrity/authentication (nonce)
    uint16_t payload_len;    // actual length of the payload
    uint8_t  payload[199];   // Payload buffer
} KnockPacket;

typedef struct {
  void (*init)(void);                             // Library init
  void (*shutdown)(void);                         // Library shutdown
  int  (*pack)(const KnockPacket *pkt, uint8_t *out_buf, size_t maxlen);  // Serialize
  int  (*unpack)(const uint8_t *buf, size_t buflen, KnockPacket *pkt);    // Deserialize
  int  (*validate)(const KnockPacket *pkt);        // Validate fields
  int (*deserialize)(const uint8_t *decrypted_buffer, size_t decrypted_len, KnockPacket *pkt);
  const char *(*deserialize_strerror)(int code);
} Payload;

// Accessor
const Payload *get_payload_lib(void);

// Return codes for deserialize
#define SL_PAYLOAD_OK              0
#define SL_PAYLOAD_ERR_NULL_PTR   -1
#define SL_PAYLOAD_ERR_UNPACK     -2
#define SL_PAYLOAD_ERR_VALIDATE   -3

#endif // SIGLATCH_PAYLOAD_H
