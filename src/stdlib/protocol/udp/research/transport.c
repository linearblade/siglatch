/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transport.h"

#include <stdlib.h>
#include <string.h>

/*
 * Internal opaque structs
 * ----------------------
 * Keep runtime state explicit and instance-based.
 * This is only skeleton state for now.
 */

struct SlTransportInstance {
  SlTransportContext ctx;
  SlTransportHooks hooks;

  uint64_t next_session_id_value;
  uint64_t next_message_id_value;
  uint32_t next_stream_id_value;
};

struct SlTransportPeer {
  SlTransportEndpoint endpoint;
  time_t last_seen;
};

struct SlTransportRxMsg {
  SlTransportReassemblyInfo info;
};

struct SlTransportTxMsg {
  SlTransportTransmitInfo info;
};

struct SlTransportSession {
  uint64_t session_id;
  SlTransportEndpoint remote;
  SlTransportStreamMode mode;
  time_t created_at;
  time_t last_seen;
};

/*
 * Global library context
 * ----------------------
 * Singleton-style installer surface, matching existing stdlib pattern.
 */

static SlTransportContext g_transport_ctx = {
  .log = NULL,
  .print = NULL,
  .role = SL_TRANSPORT_ROLE_NONE,
  .max_packet_size = SL_TRANSPORT_MAX_PACKET_SIZE,
  .default_chunk_size = SL_TRANSPORT_DEFAULT_CHUNK_SIZE,
  .max_inflight_messages = 0,
  .max_reassembly_bytes = 0,
  .max_message_bytes = 0,
  .reassembly_ttl_seconds = SL_TRANSPORT_DEFAULT_REASSEMBLY_TTL,
  .session_ttl_seconds = SL_TRANSPORT_DEFAULT_SESSION_TTL,
  .enable_ack = 0,
  .enable_retransmit = 0,
  .enable_keepalive = 0,
  .allow_out_of_order = 0
};

static void transport_set_defaults(void) {
  memset(&g_transport_ctx, 0, sizeof(g_transport_ctx));
  g_transport_ctx.role = SL_TRANSPORT_ROLE_NONE;
  g_transport_ctx.max_packet_size = SL_TRANSPORT_MAX_PACKET_SIZE;
  g_transport_ctx.default_chunk_size = SL_TRANSPORT_DEFAULT_CHUNK_SIZE;
  g_transport_ctx.reassembly_ttl_seconds = SL_TRANSPORT_DEFAULT_REASSEMBLY_TTL;
  g_transport_ctx.session_ttl_seconds = SL_TRANSPORT_DEFAULT_SESSION_TTL;
}

static void transport_set_context(const SlTransportContext *ctx) {
  if (ctx) {
    g_transport_ctx = *ctx;
  } else {
    transport_set_defaults();
  }
}

static void transport_init(const SlTransportContext *ctx) {
  transport_set_context(ctx);
}

static void transport_shutdown(void) {
  /* skeleton: no global teardown yet */
}

/*
 * Instance lifecycle
 * ------------------
 */

static SlTransportInstance *transport_instance_create(const SlTransportContext *ctx) {
  SlTransportInstance *inst = NULL;

  inst = (SlTransportInstance *)calloc(1, sizeof(*inst));
  if (!inst) {
    return NULL;
  }

  if (ctx) {
    inst->ctx = *ctx;
  } else {
    inst->ctx = g_transport_ctx;
  }

  inst->next_session_id_value = 1;
  inst->next_message_id_value = 1;
  inst->next_stream_id_value = 1;

  return inst;
}

static void transport_instance_destroy(SlTransportInstance *inst) {
  if (!inst) {
    return;
  }

  free(inst);
}

static int transport_instance_reset(SlTransportInstance *inst) {
  SlTransportContext saved_ctx;

  if (!inst) {
    return 0;
  }

  saved_ctx = inst->ctx;
  memset(inst, 0, sizeof(*inst));
  inst->ctx = saved_ctx;
  inst->next_session_id_value = 1;
  inst->next_message_id_value = 1;
  inst->next_stream_id_value = 1;

  return 1;
}

static int transport_instance_set_hooks(SlTransportInstance *inst, const SlTransportHooks *hooks) {
  if (!inst) {
    return 0;
  }

  if (hooks) {
    inst->hooks = *hooks;
  } else {
    memset(&inst->hooks, 0, sizeof(inst->hooks));
  }

  return 1;
}

/*
 * Header / packet helpers
 * -----------------------
 */

static int transport_header_init(SlTransportPacketHeader *hdr) {
  if (!hdr) {
    return 0;
  }

  memset(hdr, 0, sizeof(*hdr));
  hdr->version = 1;
  hdr->header_len = (uint16_t)sizeof(*hdr);

  return 1;
}

static int transport_header_encode(const SlTransportPacketHeader *hdr,
                                   uint8_t *out,
                                   size_t out_size,
                                   size_t *written) {
  (void)hdr;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  return 0;
}

static int transport_header_decode(SlTransportPacketHeader *out,
                                   const uint8_t *buf,
                                   size_t buf_len) {
  (void)buf;
  (void)buf_len;

  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  return 0;
}

static int transport_packet_wrap(const SlTransportPacketHeader *hdr,
                                 const uint8_t *payload,
                                 size_t payload_len,
                                 uint8_t *out,
                                 size_t out_size,
                                 size_t *written) {
  (void)hdr;
  (void)payload;
  (void)payload_len;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  return 0;
}

static int transport_packet_view(const uint8_t *buf,
                                 size_t buf_len,
                                 SlTransportPacketView *out) {
  (void)buf;
  (void)buf_len;

  if (!out) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  return 0;
}

/*
 * ID helpers
 * ----------
 */

static uint64_t transport_next_session_id(SlTransportInstance *inst) {
  if (!inst) {
    return 0;
  }

  return inst->next_session_id_value++;
}

static uint64_t transport_next_message_id(SlTransportInstance *inst) {
  if (!inst) {
    return 0;
  }

  return inst->next_message_id_value++;
}

static uint32_t transport_next_stream_id(SlTransportInstance *inst) {
  if (!inst) {
    return 0;
  }

  return inst->next_stream_id_value++;
}

static size_t transport_recommended_chunk_size(const SlTransportInstance *inst) {
  if (!inst) {
    return SL_TRANSPORT_DEFAULT_CHUNK_SIZE;
  }

  if (inst->ctx.default_chunk_size > 0) {
    return inst->ctx.default_chunk_size;
  }

  return SL_TRANSPORT_DEFAULT_CHUNK_SIZE;
}

static int transport_calc_fragment_count(size_t total_len,
                                         size_t chunk_size,
                                         uint16_t *out_count) {
  size_t count = 0;

  if (!out_count || chunk_size == 0) {
    return 0;
  }

  count = (total_len + chunk_size - 1) / chunk_size;
  if (count > 0xFFFFu) {
    return 0;
  }

  *out_count = (uint16_t)count;
  return 1;
}

/*
 * Ingress / egress
 * ----------------
 */

static int transport_ingest_datagram(SlTransportInstance *inst,
                                     const SlTransportEndpoint *remote,
                                     const uint8_t *buf,
                                     size_t buf_len) {
  (void)inst;
  (void)remote;
  (void)buf;
  (void)buf_len;
  return 0;
}

static int transport_build_single(SlTransportInstance *inst,
                                  const SlTransportMessage *msg,
                                  uint8_t *out,
                                  size_t out_size,
                                  size_t *written) {
  (void)inst;
  (void)msg;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  return 0;
}

static int transport_begin_send(SlTransportInstance *inst,
                                const SlTransportEndpoint *remote,
                                const SlTransportMessage *msg,
                                SlTransportTxMsg **out_tx) {
  (void)inst;
  (void)remote;
  (void)msg;

  if (out_tx) {
    *out_tx = NULL;
  }

  return 0;
}

static int transport_next_send_chunk(SlTransportInstance *inst,
                                     SlTransportTxMsg *tx,
                                     uint8_t *out,
                                     size_t out_size,
                                     size_t *written,
                                     int *done) {
  (void)inst;
  (void)tx;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  if (done) {
    *done = 1;
  }

  return 0;
}

static int transport_recv_complete(SlTransportInstance *inst,
                                   SlTransportRxMsg *rx,
                                   SlTransportMessage *out_msg) {
  (void)inst;
  (void)rx;

  if (!out_msg) {
    return 0;
  }

  memset(out_msg, 0, sizeof(*out_msg));
  return 0;
}

/*
 * ACK / retransmit / timers
 * -------------------------
 */

static int transport_build_ack(SlTransportInstance *inst,
                               uint64_t session_id,
                               uint64_t message_id,
                               uint32_t stream_id,
                               uint32_t ack_base,
                               uint32_t ack_bits,
                               uint8_t *out,
                               size_t out_size,
                               size_t *written) {
  (void)inst;
  (void)session_id;
  (void)message_id;
  (void)stream_id;
  (void)ack_base;
  (void)ack_bits;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  return 0;
}

static int transport_mark_acked(SlTransportInstance *inst,
                                uint64_t session_id,
                                uint64_t message_id,
                                uint32_t stream_id,
                                uint32_t ack_base,
                                uint32_t ack_bits) {
  (void)inst;
  (void)session_id;
  (void)message_id;
  (void)stream_id;
  (void)ack_base;
  (void)ack_bits;
  return 0;
}

static int transport_poll_retransmit(SlTransportInstance *inst,
                                     uint8_t *out,
                                     size_t out_size,
                                     size_t *written) {
  (void)inst;
  (void)out;
  (void)out_size;

  if (written) {
    *written = 0;
  }

  return 0;
}

static int transport_tick(SlTransportInstance *inst, time_t now) {
  (void)inst;
  (void)now;
  return 1;
}

/*
 * Session management
 * ------------------
 */

static int transport_session_open(SlTransportInstance *inst,
                                  const SlTransportEndpoint *remote,
                                  SlTransportStreamMode mode,
                                  uint64_t *out_session_id) {
  (void)remote;
  (void)mode;

  if (!inst || !out_session_id) {
    return 0;
  }

  *out_session_id = transport_next_session_id(inst);
  return 1;
}

static int transport_session_close(SlTransportInstance *inst, uint64_t session_id) {
  (void)inst;
  (void)session_id;
  return 0;
}

static int transport_session_touch(SlTransportInstance *inst, uint64_t session_id) {
  (void)inst;
  (void)session_id;
  return 0;
}

/*
 * Diagnostics
 * -----------
 */

static int transport_rx_info(const SlTransportRxMsg *rx, SlTransportReassemblyInfo *out) {
  if (!rx || !out) {
    return 0;
  }

  *out = rx->info;
  return 1;
}

static int transport_tx_info(const SlTransportTxMsg *tx, SlTransportTransmitInfo *out) {
  if (!tx || !out) {
    return 0;
  }

  *out = tx->info;
  return 1;
}

static const char *transport_error_string(SlTransportError err) {
  switch (err) {
  case SL_TRANSPORT_OK:                return "ok";
  case SL_TRANSPORT_ERR_INVALID_ARG:   return "invalid argument";
  case SL_TRANSPORT_ERR_STATE:         return "invalid state";
  case SL_TRANSPORT_ERR_NOMEM:         return "out of memory";
  case SL_TRANSPORT_ERR_IO:            return "io error";
  case SL_TRANSPORT_ERR_TIMEOUT:       return "timeout";
  case SL_TRANSPORT_ERR_OVERFLOW:      return "overflow";
  case SL_TRANSPORT_ERR_NOT_FOUND:     return "not found";
  case SL_TRANSPORT_ERR_UNSUPPORTED:   return "unsupported";
  case SL_TRANSPORT_ERR_INTERNAL:      return "internal error";
  default:                             return "unknown error";
  }
}

/*
 * Installed singleton instance
 * ----------------------------
 */

static const SlTransportLib transport_instance = {
  .init = transport_init,
  .shutdown = transport_shutdown,
  .set_context = transport_set_context,

  .instance_create = transport_instance_create,
  .instance_destroy = transport_instance_destroy,
  .instance_reset = transport_instance_reset,
  .instance_set_hooks = transport_instance_set_hooks,

  .header_init = transport_header_init,
  .header_encode = transport_header_encode,
  .header_decode = transport_header_decode,

  .packet_wrap = transport_packet_wrap,
  .packet_view = transport_packet_view,

  .next_session_id = transport_next_session_id,
  .next_message_id = transport_next_message_id,
  .next_stream_id = transport_next_stream_id,

  .recommended_chunk_size = transport_recommended_chunk_size,
  .calc_fragment_count = transport_calc_fragment_count,

  .ingest_datagram = transport_ingest_datagram,
  .build_single = transport_build_single,
  .begin_send = transport_begin_send,
  .next_send_chunk = transport_next_send_chunk,
  .recv_complete = transport_recv_complete,

  .build_ack = transport_build_ack,
  .mark_acked = transport_mark_acked,
  .poll_retransmit = transport_poll_retransmit,
  .tick = transport_tick,

  .session_open = transport_session_open,
  .session_close = transport_session_close,
  .session_touch = transport_session_touch,

  .rx_info = transport_rx_info,
  .tx_info = transport_tx_info,

  .error_string = transport_error_string
};

const SlTransportLib *get_lib_transport(void) {
  return &transport_instance;
}
