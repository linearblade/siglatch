/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX2_INTERNAL_H
#define LIB_PROTOCOL_UDP_M7MUX2_INTERNAL_H

#include "connect/connect.h"
#include "ingress/ingress.h"
#include "inbox/inbox.h"
#include "normalize/normalize.h"
#include "session/session.h"
#include "outbox/outbox.h"
#include "stream/stream.h"
#include "egress/egress.h"

/*
 * Connection state is caller-owned runtime data.
 * The module context stays in the singleton service, not inside the state.
 */
typedef struct M7Mux2ConnectState {
  int socket_fd;
  int owns_socket;
  int connected;
  char remote_ip[64];
  uint16_t remote_port;
} M7Mux2ConnectState;

typedef struct M7Mux2State {
  M7Mux2ConnectState connect;
  M7Mux2IngressState ingress;
  M7Mux2SessionState session;
  M7Mux2StreamState stream;
  M7Mux2EgressState egress;
} M7Mux2State;

typedef struct M7Mux2InternalLib {
  const M7Mux2ConnectLib *connect;
  const M7Mux2InboxLib *inbox;
  const M7Mux2OutboxLib *outbox;
  const M7Mux2IngressLib *ingress;
  const M7Mux2NormalizeLib *normalize;
  const M7Mux2SessionLib *session;
  const M7Mux2StreamLib *stream;
  const M7Mux2EgressLib *egress;
} M7Mux2InternalLib;

#endif
