/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "../m7mux.h"
#include "../internal.h"

#include <stdlib.h>
#include <string.h>

static M7MuxContext g_ctx = {0};
static void m7mux_connect_shutdown(void);

static const M7MuxInternalLib *m7mux_connect_internal(void) {
  return g_ctx.internal;
}

static int m7mux_connect_validate_context(const M7MuxContext *ctx) {
  const M7MuxInternalLib *internal = NULL;

  if (!ctx || !ctx->socket || !ctx->udp || !ctx->internal) {
    return 0;
  }

  if (!ctx->socket->close || !ctx->udp->open_auto) {
    return 0;
  }

  internal = ctx->internal;
  return internal->inbox && internal->outbox &&
         internal->inbox->state_init && internal->inbox->state_reset &&
         internal->outbox->state_init && internal->outbox->state_reset;
}

static void m7mux_connect_copy_ip(char *dst, size_t dst_len, const char *src) {
  if (!dst || dst_len == 0u) {
    return;
  }

  memset(dst, 0, dst_len);
  if (src) {
    strncpy(dst, src, dst_len - 1u);
  }
}

static int m7mux_connect_apply_context(const M7MuxContext *ctx) {
  if (!ctx) {
    return 0;
  }

  g_ctx = *ctx;
  return 1;
}

static int m7mux_connect_init(const M7MuxContext *ctx) {
  if (!m7mux_connect_validate_context(ctx)) {
    m7mux_connect_shutdown();
    return 0;
  }

  return m7mux_connect_apply_context(ctx);
}

static int m7mux_connect_set_context(const M7MuxContext *ctx) {
  if (!m7mux_connect_validate_context(ctx)) {
    m7mux_connect_shutdown();
    return 0;
  }

  return m7mux_connect_apply_context(ctx);
}

static void m7mux_connect_shutdown(void) {
  memset(&g_ctx, 0, sizeof(g_ctx));
}

static int m7mux_connect_state_init(M7MuxState *state) {
  const M7MuxInternalLib *internal = NULL;

  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  state->connect.socket_fd = -1;

  internal = m7mux_connect_internal();
  if (!internal || !internal->inbox || !internal->outbox ||
      !internal->inbox->state_init || !internal->outbox->state_init) {
    return 0;
  }

  if (!internal->inbox->state_init(state)) {
    return 0;
  }

  if (!internal->outbox->state_init(state)) {
    if (internal->inbox->state_reset) {
      internal->inbox->state_reset(state);
    }
    if (internal->outbox->state_reset) {
      internal->outbox->state_reset(state);
    }
    return 0;
  }

  return 1;
}

static void m7mux_connect_state_reset(M7MuxState *state) {
  const M7MuxInternalLib *internal = NULL;

  if (!state) {
    return;
  }

  internal = m7mux_connect_internal();
  if (internal && internal->outbox && internal->outbox->state_reset) {
    internal->outbox->state_reset(state);
  } else {
    memset(&state->egress, 0, sizeof(state->egress));
  }

  if (internal && internal->inbox && internal->inbox->state_reset) {
    internal->inbox->state_reset(state);
  } else {
    memset(&state->ingress, 0, sizeof(state->ingress));
    memset(&state->stream, 0, sizeof(state->stream));
  }

  memset(&state->connect, 0, sizeof(state->connect));
  state->connect.socket_fd = -1;
}

static M7MuxState *m7mux_connect_alloc_state(void) {
  M7MuxState *state = NULL;

  state = (M7MuxState *)calloc(1, sizeof(*state));
  if (!state) {
    return NULL;
  }

  if (!m7mux_connect_state_init(state)) {
    free(state);
    return NULL;
  }

  return state;
}

static M7MuxState *m7mux_connect_ip(const char *ip, uint16_t port) {
  M7MuxState *state = NULL;
  int socket_fd = -1;

  if (!g_ctx.udp || !g_ctx.udp->open_auto || !ip || ip[0] == '\0') {
    return NULL;
  }

  state = m7mux_connect_alloc_state();
  if (!state) {
    return NULL;
  }

  socket_fd = g_ctx.udp->open_auto(ip);
  if (socket_fd < 0) {
    free(state);
    return NULL;
  }

  state->connect.socket_fd = socket_fd;
  state->connect.owns_socket = 1;
  state->connect.connected = 1;
  m7mux_connect_copy_ip(state->connect.remote_ip, sizeof(state->connect.remote_ip), ip);
  state->connect.remote_port = port;

  return state;
}

static M7MuxState *m7mux_connect_socket(int socket_fd) {
  M7MuxState *state = NULL;

  if (socket_fd < 0) {
    return NULL;
  }

  state = m7mux_connect_alloc_state();
  if (!state) {
    return NULL;
  }

  state->connect.socket_fd = socket_fd;
  state->connect.owns_socket = 0;
  state->connect.connected = 1;

  return state;
}

static void m7mux_connect_disconnect(M7MuxState *state) {
  if (!state) {
    return;
  }

  if (state->connect.owns_socket &&
      state->connect.socket_fd >= 0 &&
      g_ctx.socket &&
      g_ctx.socket->close) {
    g_ctx.socket->close(state->connect.socket_fd);
  }

  m7mux_connect_state_reset(state);
  free(state);
}

static const M7MuxConnectLib _instance = {
  .init = m7mux_connect_init,
  .set_context = m7mux_connect_set_context,
  .shutdown = m7mux_connect_shutdown,
  .state_init = m7mux_connect_state_init,
  .state_reset = m7mux_connect_state_reset,
  .connect_ip = m7mux_connect_ip,
  .connect_socket = m7mux_connect_socket,
  .disconnect = m7mux_connect_disconnect
};

const M7MuxConnectLib *get_protocol_udp_m7mux_connect_lib(void) {
  return &_instance;
}
