/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H

#include <stddef.h>
#include <stdint.h>

#include "../../../time.h"
#include "../../../net/socket/socket.h"
#include "../../../net/udp/udp.h"

/**
 * @file m7mux.h
 * @brief Minimal UDP mux spine for session/stream/message transport.
 *
 * This is intentionally small for now. It only carries lifecycle and context
 * wiring so we can grow the transport layer without dragging protocol details
 * into the app layer.
 */

typedef struct {
  const SocketLib *socket;
  const UdpLib *udp;
  const TimeLib *time;
  void *reserved;
} M7MuxContext;

typedef struct M7MuxRecvContext M7MuxRecvContext;

typedef int (*M7MuxDemuxFn)(
    const uint8_t *input,
    size_t input_len,
    void *route,
    size_t route_len);

typedef int (*M7MuxNormalizeFn)(
    const void *route,
    size_t route_len,
    const uint8_t *input,
    size_t input_len,
    const char *ip,
    uint16_t port,
    int encrypted,
    M7MuxRecvContext *out);

typedef struct {
  const char *name;
  M7MuxNormalizeFn normalize;
  void *reserved;
} M7MuxAdapter;

typedef struct {
  const char *name;
  const char *adapter_name;
  M7MuxDemuxFn detect;
  size_t route_len;
  void *reserved;
} M7MuxDemux;

typedef struct {
  char ip[64];
  uint16_t port;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t flags;
} M7MuxSendContext;

struct M7MuxRecvContext {
  int complete;
  uint32_t wire_version;
  uint8_t wire_form;
  uint64_t received_ms;
  char ip[64];
  uint16_t port;
  uint64_t session_id;
  uint64_t message_id;
  uint32_t stream_id;
  uint32_t fragment_index;
  uint32_t fragment_count;
  uint32_t timestamp;
  uint16_t user_id;
  uint8_t action_id;
  uint32_t challenge;
  uint8_t hmac[32];
  uint32_t flags;
  int encrypted;
  const void *payload;
  size_t payload_len;
  int final;
};

typedef struct M7MuxState M7MuxState;

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  /**
   * @brief Register a reusable packet adapter.
   */
  int (*register_adapter)(const M7MuxAdapter *adapter);

  /**
   * @brief Remove a packet adapter by name.
   */
  int (*unregister_adapter)(const char *name);

  /**
   * @brief Register a reusable packet demux rule.
   */
  int (*register_demux)(const M7MuxDemux *demux);

  /**
   * @brief Remove a packet demux rule by name.
   */
  int (*unregister_demux)(const char *name);

  /**
   * @brief Create a mux state connected to a remote endpoint.
   */
  M7MuxState *(*connect_ip)(const char *ip, uint16_t port);

  /**
   * @brief Create a mux state attached to an existing UDP socket.
   */
  M7MuxState *(*connect_socket)(int socket_fd);

  /**
   * @brief Send a payload through the mux state using explicit routing data.
   */
  int (*send)(M7MuxState *state, const M7MuxSendContext *ctx, const void *buf, size_t len);

  /**
   * @brief Receive the next normalized mux unit, if any.
   */
  int (*recv)(M7MuxState *state, M7MuxRecvContext *out);

  /**
   * @brief Advance timers and internal transport state.
   */
  int (*pump)(M7MuxState *state, uint64_t now_ms);

  /**
   * @brief Reply through the mux state using explicit outbound routing.
   */
  int (*reply)(M7MuxState *state, const M7MuxSendContext *ctx, const void *buf, size_t len);

  /**
   * @brief Reply using metadata derived from a received unit.
   */
  int (*reply_to)(M7MuxState *state, const M7MuxRecvContext *rx, const void *buf, size_t len);

  /**
   * @brief Tear down the mux state and free owned resources.
   */
  void (*disconnect)(M7MuxState *state);
} M7MuxLib;

const M7MuxLib *get_lib_m7mux(void);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H */
