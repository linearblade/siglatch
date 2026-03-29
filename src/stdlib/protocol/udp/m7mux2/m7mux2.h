/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX2_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX2_H

#include <stdint.h>

#include "../../../time.h"
#include "../../../net/socket/socket.h"
#include "../../../net/udp/udp.h"
#include "../../../../shared/knock/codec3/context.h"

/**
 * @file m7mux2.h
 * @brief Bootstrap contract for the UDP mux rig.
 *
 * This top-level surface intentionally stays small: it carries runtime context
 * and lifecycle hooks only. Packet interpretation, normalization, streaming,
 * and egress live in the nested submodules below this layer.
 */

typedef struct M7Mux2Context {
  const SocketLib *socket;
  const UdpLib *udp;
  const TimeLib *time;
  const SharedKnockCodec3Context *codec_context;
  int enforce_wire_decode;
  int enforce_wire_auth;
  const struct M7Mux2InternalLib *internal;
  void *reserved;
} M7Mux2Context;

/*
 * Opaque codec instance handle used by future codec registry work.
 * The live registry stores it as an implementation detail and never peeks
 * inside the concrete codec state layout.
 */
typedef struct M7Mux2CodecState M7Mux2CodecState;

#include "connect/connect.h"
#include "inbox/inbox.h"
#include "outbox/outbox.h"
typedef struct M7Mux2InternalLib M7Mux2InternalLib;

typedef struct {
  M7Mux2ConnectLib connect;
  M7Mux2InboxLib inbox;
  M7Mux2OutboxLib outbox;
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  int (*pump)(M7Mux2State *state, uint64_t timeout_ms);
  void (*shutdown)(void);
} M7Mux2Lib;

const M7Mux2Lib *get_lib_m7mux2(void);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX2_H */
