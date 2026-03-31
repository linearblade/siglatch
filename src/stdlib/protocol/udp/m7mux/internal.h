/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_PROTOCOL_UDP_M7MUX_INTERNAL_H
#define LIB_PROTOCOL_UDP_M7MUX_INTERNAL_H

#include "connect/connect.h"
#include "ingress/ingress.h"
#include "inbox/inbox.h"
#include "normalize/normalize.h"
#include "session/session.h"
#include "outbox/outbox.h"
#include "stream/stream.h"
#include "egress/egress.h"

typedef enum M7MuxPolicyEnforceEncryption {
  M7MUX_POLICY_ENFORCE_ENCRYPTION_ANY = 0,
  M7MUX_POLICY_ENFORCE_ENCRYPTION_YES = 1,
  M7MUX_POLICY_ENFORCE_ENCRYPTION_NO = 2
} M7MuxPolicyEnforceEncryption;

/*
 * Connection state is caller-owned runtime data.
 * The module context stays in the singleton service, not inside the state.
 */
typedef struct M7MuxConnectState {
  int socket_fd;
  int owns_socket;
  int connected;
  char remote_ip[64];
  uint16_t remote_port;
} M7MuxConnectState;

typedef struct M7MuxState {
  M7MuxConnectState connect;
  M7MuxPolicyEnforceEncryption policy_enforce_encryption;
  M7MuxIngressState ingress;
  M7MuxSessionState session;
  M7MuxStreamState stream;
  M7MuxEgressState egress;
} M7MuxState;

typedef struct M7MuxInternalLib {
  const M7MuxConnectLib *connect;
  const M7MuxInboxLib *inbox;
  const M7MuxOutboxLib *outbox;
  const M7MuxIngressLib *ingress;
  const M7MuxNormalizeLib *normalize;
  const M7MuxSessionLib *session;
  const M7MuxStreamLib *stream;
  const M7MuxEgressLib *egress;
} M7MuxInternalLib;

#endif
