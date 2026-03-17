/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_TRANSPORT_H
#define SIGLATCH_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "log.h"
#include "print.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Transport design notes:
 *
 * - Library surface is singleton-style, matching the existing stdlib pattern.
 * - Runtime transport/session/message state is explicit and instance-based.
 * - This is a skeleton only: no protocol behavior is implemented yet.
 */

/* -----------------------------
 * Limits / defaults
 * ----------------------------- */

#define SL_TRANSPORT_MAX_PACKET_SIZE        1200
#define SL_TRANSPORT_DEFAULT_CHUNK_SIZE     1024
#define SL_TRANSPORT_DEFAULT_REASSEMBLY_TTL 30
#define SL_TRANSPORT_DEFAULT_SESSION_TTL    60

/* -----------------------------
 * Forward declarations / opaque handles
 * ----------------------------- */

typedef struct SlTransportInstance SlTransportInstance;
typedef struct SlTransportPeer     SlTransportPeer;
typedef struct SlTransportRxMsg    SlTransportRxMsg;
typedef struct SlTransportTxMsg    SlTransportTxMsg;
typedef struct SlTransportSession  SlTransportSession;

/* -----------------------------
 * Common enums
 * ----------------------------- */

typedef enum {
  SL_TRANSPORT_OK = 0,
  SL_TRANSPORT_ERR_INVALID_ARG,
  SL_TRANSPORT_ERR_STATE,
  SL_TRANSPORT_ERR_NOMEM,
  SL_TRANSPORT_ERR_IO,
  SL_TRANSPORT_ERR_TIMEOUT,
  SL_TRANSPORT_ERR_OVERFLOW,
  SL_TRANSPORT_ERR_NOT_FOUND,
  SL_TRANSPORT_ERR_UNSUPPORTED,
  SL_TRANSPORT_ERR_INTERNAL
} SlTransportError;

typedef enum {
  SL_TRANSPORT_ROLE_NONE = 0,
  SL_TRANSPORT_ROLE_CLIENT,
  SL_TRANSPORT_ROLE_SERVER
} SlTransportRole;

typedef enum {
  SL_TRANSPORT_PKT_NONE        = 0,
  SL_TRANSPORT_PKT_SINGLE      = 1,
  SL_TRANSPORT_PKT_FRAGMENT    = 2,
  SL_TRANSPORT_PKT_ACK         = 3,
  SL_TRANSPORT_PKT_NACK        = 4,
  SL_TRANSPORT_PKT_OPEN        = 5,
  SL_TRANSPORT_PKT_CLOSE       = 6,
  SL_TRANSPORT_PKT_KEEPALIVE   = 7,
  SL_TRANSPORT_PKT_DATA        = 8,
  SL_TRANSPORT_PKT_CONTROL     = 9
} SlTransportPacketType;

typedef enum {
  SL_TRANSPORT_MSG_NONE      = 0,
  SL_TRANSPORT_MSG_SINGLE    = 1,
  SL_TRANSPORT_MSG_BLOB      = 2,
  SL_TRANSPORT_MSG_FILE      = 3,
  SL_TRANSPORT_MSG_STREAM    = 4,
  SL_TRANSPORT_MSG_CONTROL   = 5
} SlTransportMessageType;

typedef enum {
  SL_TRANSPORT_DELIVERY_BEST_EFFORT = 0,
  SL_TRANSPORT_DELIVERY_RELIABLE    = 1
} SlTransportDeliveryMode;

typedef enum {
  SL_TRANSPORT_STREAM_NONE = 0,
  SL_TRANSPORT_STREAM_HALF,
  SL_TRANSPORT_STREAM_FULL
} SlTransportStreamMode;

/* -----------------------------
 * Endpoint / IDs
 * ----------------------------- */

typedef struct {
  char     ip[64];
  uint16_t port;
} SlTransportEndpoint;

typedef struct {
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
} SlTransportIds;

/* -----------------------------
 * Context / config
 * ----------------------------- */

typedef struct {
  const Logger   *log;
  const PrintLib *print;

  SlTransportRole role;

  size_t max_packet_size;
  size_t default_chunk_size;

  size_t max_inflight_messages;
  size_t max_reassembly_bytes;
  size_t max_message_bytes;

  time_t reassembly_ttl_seconds;
  time_t session_ttl_seconds;

  int enable_ack;
  int enable_retransmit;
  int enable_keepalive;
  int allow_out_of_order;
} SlTransportContext;

/* -----------------------------
 * Packet / message skeleton types
 * ----------------------------- */
  /*
    session
   ├── stream
   │      ├── message
   │      └── message
   │
   └── stream
          ├── message
          └── message

	  sessions should be a random id to minimize collisions etc.
   */

  
typedef struct {
  uint8_t  version;
  uint8_t  packet_type;
  uint16_t header_len;
  uint32_t flags;

  uint64_t session_id;
  uint64_t message_id;

  uint32_t stream_id;
  uint16_t fragment_index;
  uint16_t fragment_count;

  uint32_t payload_len;
  uint32_t payload_total_len;

  uint32_t ack_base;
  uint32_t ack_bits;
} SlTransportPacketHeader;

typedef struct {
  SlTransportPacketHeader header;
  const uint8_t *payload;
  size_t payload_len;
} SlTransportPacketView;

typedef struct {
  SlTransportMessageType   type;
  SlTransportDeliveryMode  delivery;
  SlTransportStreamMode    stream_mode;

  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;

  const uint8_t *data;
  size_t data_len;
} SlTransportMessage;

typedef struct {
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  size_t bytes_received;
  size_t bytes_expected;
  uint16_t fragments_received;
  uint16_t fragments_expected;
  time_t created_at;
  time_t expires_at;
} SlTransportReassemblyInfo;
  
typedef struct {
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  size_t bytes_sent;
  size_t bytes_acked;
  uint16_t fragments_sent;
  uint16_t fragments_acked;
  time_t created_at;
  time_t last_send_at;
} SlTransportTransmitInfo;

/* -----------------------------
 * Callback hooks
 * ----------------------------- */

typedef struct {
  void (*on_packet_rx)(SlTransportInstance *inst,
                       const SlTransportEndpoint *remote,
                       const SlTransportPacketView *pkt);

  void (*on_message_complete)(SlTransportInstance *inst,
                              const SlTransportEndpoint *remote,
                              const SlTransportMessage *msg);

  void (*on_ack)(SlTransportInstance *inst,
                 uint64_t session_id,
                 uint64_t message_id,
                 uint32_t stream_id);

  void (*on_error)(SlTransportInstance *inst,
                   SlTransportError err,
                   const char *where);
} SlTransportHooks;

/* -----------------------------
 * Public library API
 * ----------------------------- */

typedef struct {
  void (*init)(const SlTransportContext *ctx);
  void (*shutdown)(void);
  void (*set_context)(const SlTransportContext *ctx);

  /* instance lifecycle */
  SlTransportInstance *(*instance_create)(const SlTransportContext *ctx);
  void (*instance_destroy)(SlTransportInstance *inst);
  int (*instance_reset)(SlTransportInstance *inst);
  int (*instance_set_hooks)(SlTransportInstance *inst, const SlTransportHooks *hooks);

  /* packet encode/decode */
  int (*header_init)(SlTransportPacketHeader *hdr);
  int (*header_encode)(const SlTransportPacketHeader *hdr, uint8_t *out, size_t out_size, size_t *written);
  int (*header_decode)(SlTransportPacketHeader *out, const uint8_t *buf, size_t buf_len);

  int (*packet_wrap)(const SlTransportPacketHeader *hdr,
                     const uint8_t *payload,
                     size_t payload_len,
                     uint8_t *out,
                     size_t out_size,
                     size_t *written);

  int (*packet_view)(const uint8_t *buf,
                     size_t buf_len,
                     SlTransportPacketView *out);

  /* ids / helpers */
  uint64_t (*next_session_id)(SlTransportInstance *inst);
  uint64_t (*next_message_id)(SlTransportInstance *inst);
  uint32_t (*next_stream_id)(SlTransportInstance *inst);

  size_t (*recommended_chunk_size)(const SlTransportInstance *inst);
  int (*calc_fragment_count)(size_t total_len, size_t chunk_size, uint16_t *out_count);

  /* ingress / egress */
  int (*ingest_datagram)(SlTransportInstance *inst,
                         const SlTransportEndpoint *remote,
                         const uint8_t *buf,
                         size_t buf_len);

  int (*build_single)(SlTransportInstance *inst,
                      const SlTransportMessage *msg,
                      uint8_t *out,
                      size_t out_size,
                      size_t *written);

  int (*begin_send)(SlTransportInstance *inst,
                    const SlTransportEndpoint *remote,
                    const SlTransportMessage *msg,
                    SlTransportTxMsg **out_tx);

  int (*next_send_chunk)(SlTransportInstance *inst,
                         SlTransportTxMsg *tx,
                         uint8_t *out,
                         size_t out_size,
                         size_t *written,
                         int *done);

  int (*recv_complete)(SlTransportInstance *inst,
                       SlTransportRxMsg *rx,
                       SlTransportMessage *out_msg);

  /* ack / retransmit / timers */
  int (*build_ack)(SlTransportInstance *inst,
                   uint64_t session_id,
                   uint64_t message_id,
                   uint32_t stream_id,
                   uint32_t ack_base,
                   uint32_t ack_bits,
                   uint8_t *out,
                   size_t out_size,
                   size_t *written);

  int (*mark_acked)(SlTransportInstance *inst,
                    uint64_t session_id,
                    uint64_t message_id,
                    uint32_t stream_id,
                    uint32_t ack_base,
                    uint32_t ack_bits);

  int (*poll_retransmit)(SlTransportInstance *inst,
                         uint8_t *out,
                         size_t out_size,
                         size_t *written);

  int (*tick)(SlTransportInstance *inst, time_t now);

  /* session management */
  int (*session_open)(SlTransportInstance *inst,
                      const SlTransportEndpoint *remote,
                      SlTransportStreamMode mode,
                      uint64_t *out_session_id);

  int (*session_close)(SlTransportInstance *inst, uint64_t session_id);
  int (*session_touch)(SlTransportInstance *inst, uint64_t session_id);

  /* info / diagnostics */
  int (*rx_info)(const SlTransportRxMsg *rx, SlTransportReassemblyInfo *out);
  int (*tx_info)(const SlTransportTxMsg *tx, SlTransportTransmitInfo *out);

  const char *(*error_string)(SlTransportError err);
} SlTransportLib;

/* -----------------------------
 * Accessor
 * ----------------------------- */

const SlTransportLib *get_lib_transport(void);

#ifdef __cplusplus
}
#endif

#endif /* SIGLATCH_TRANSPORT_H */
