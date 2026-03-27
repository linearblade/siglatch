/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H
#define SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H

#include <stdint.h>

#include "../../../time.h"
#include "../../../net/socket/socket.h"
#include "../../../net/udp/udp.h"
#include "../../../../shared/knock/codec2/context.h"

/**
 * @file m7mux.h
 * @brief Bootstrap contract for the UDP mux rig.
 *
 * This top-level surface intentionally stays small: it carries runtime context
 * and lifecycle hooks only. Packet interpretation, normalization, streaming,
 * and egress live in the nested submodules below this layer.
 */

typedef struct M7MuxContext {
  const SocketLib *socket;
  const UdpLib *udp;
  const TimeLib *time;
  const SharedKnockCodecContext *codec_context;
  const struct M7MuxInternalLib *internal;
  void *reserved;
} M7MuxContext;

/*
 * Opaque codec instance handle used by future codec registry work.
 * The live registry stores it as an implementation detail and never peeks
 * inside the concrete codec state layout.
 */
typedef struct M7MuxCodecState M7MuxCodecState;

#include "connect/connect.h"
#include "inbox/inbox.h"
#include "outbox/outbox.h"
typedef struct M7MuxInternalLib M7MuxInternalLib;

typedef struct {
  M7MuxConnectLib connect;
  M7MuxInboxLib inbox;
  M7MuxOutboxLib outbox;
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  int (*pump)(M7MuxState *state, uint64_t timeout_ms);
  void (*shutdown)(void);
} M7MuxLib;

const M7MuxLib *get_lib_m7mux(void);

#endif /* SIGLATCH_STDLIB_PROTOCOL_UDP_M7MUX_H */
