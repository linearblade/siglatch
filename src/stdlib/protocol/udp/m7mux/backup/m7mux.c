/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "m7mux.h"
#include "normalize/backup/decode/decode.h"
#include "normalize/backup/demux/demux.h"
#include "listener/listener.h"

#include <stdlib.h>
#include <string.h>

static M7MuxContext g_m7mux_ctx = {0};
static const M7MuxDemuxLib *g_demux_lib = NULL;
static const M7MuxDecodeLib *g_decode_lib = NULL;

struct M7MuxState {
  M7MuxListenerState    listener;
  M7MuxSessionState     session;
  M7MuxOutboundState    outbound;
  M7MuxLocalIntentState local_intent;
  M7MuxDecodeState      decode;
  M7MuxDemuxState       demux;
  M7MuxStreamState      stream;
};


static void m7mux_reset_context(void) {
  memset(&g_m7mux_ctx, 0, sizeof(g_m7mux_ctx));
}

static int m7mux_apply_context(const M7MuxContext *ctx) {
  g_m7mux_ctx = *ctx;
  return 1;
}

size_t m7mux_demux_count(void) {
  return g_demux_lib->count();
}

const M7MuxDemux *m7mux_demux_at(size_t index) {
  return g_demux_lib->at(index);
}

const M7MuxAdapter *m7mux_lookup_adapter(const char *name) {
  return g_decode_lib->lookup_adapter(name);
}

static int m7mux_init(const M7MuxContext *ctx) {
  m7mux_apply_context(ctx);
  g_demux_lib = get_lib_m7mux_demux();
  g_decode_lib = get_lib_m7mux_decode();
  g_demux_lib->init(&g_m7mux_ctx);
  g_decode_lib->init(&g_m7mux_ctx);

  return 1;
}

static int m7mux_set_context(const M7MuxContext *ctx) {
  m7mux_apply_context(ctx);

  g_demux_lib->set_context(&g_m7mux_ctx);
  g_decode_lib->set_context(&g_m7mux_ctx);

  return 1;
}

static void m7mux_shutdown(void) {
  g_demux_lib->shutdown();
  g_decode_lib->shutdown();

  g_demux_lib = NULL;
  g_decode_lib = NULL;
  m7mux_reset_context();
}

static int m7mux_register_adapter(const M7MuxAdapter *adapter) {
  return g_decode_lib->register_adapter(adapter);
}

static int m7mux_unregister_adapter(const char *name) {
  return g_decode_lib->unregister_adapter(name);
}

static int m7mux_register_demux(const M7MuxDemux *demux) {
  return g_demux_lib->register_demux(demux);
}

static int m7mux_unregister_demux(const char *name) {
  return g_demux_lib->unregister_demux(name);
}

static M7MuxState *m7mux_state_alloc(void) {
  M7MuxState *state = (M7MuxState *)calloc(1, sizeof(*state));

  if (!state) {
    return NULL;
  }

  state->ctx = &g_m7mux_ctx;
  state->socket_fd = -1;
  state->next_session_id = 1;
  state->next_message_id = 1;
  state->next_stream_id = 1;

  return state;
}

static void m7mux_copy_ip(char *dst, size_t dst_len, const char *src) {
  if (dst_len == 0) {
    return;
  }

  memset(dst, 0, dst_len);
  strncpy(dst, src, dst_len - 1);
}

static void m7mux_fill_identity(M7MuxState *state,
                                const M7MuxListenerIngress *ingress,
                                M7MuxRecvContext *out) {
  if (out->ip[0] == '\0') {
    m7mux_copy_ip(out->ip, sizeof(out->ip), ingress->ip);
  }
  if (out->port == 0) {
    out->port = ingress->port;
  }
  if (out->session_id == 0) {
    if (state->session_id == 0) {
      state->session_id = state->next_session_id++;
    }
    out->session_id = state->session_id;
  }
  if (out->message_id == 0) {
    out->message_id = state->next_message_id++;
  }
  if (out->stream_id == 0) {
    out->stream_id = state->next_stream_id++;
  }
  out->encrypted = ingress->encrypted;
}

static M7MuxState *m7mux_connect_ip(const char *ip, uint16_t port) {
  M7MuxState *state = NULL;

  state = m7mux_state_alloc();
  state->socket_fd = g_m7mux_ctx.udp->open_auto(ip);

  state->owns_socket = 1;
  state->connected = 1;
  m7mux_copy_ip(state->remote_ip, sizeof(state->remote_ip), ip);
  state->remote_port = port;

  return state;
}

static M7MuxState *m7mux_connect_socket(int socket_fd) {
  M7MuxState *state = NULL;

  state = m7mux_state_alloc();
  state->socket_fd = socket_fd;
  state->owns_socket = 0;
  state->connected = 1;

  return state;
}

static int m7mux_send(M7MuxState *state, const M7MuxSendContext *ctx, const void *buf, size_t len) {
  const char *target_ip = NULL;
  uint16_t target_port = 0;

  if (ctx->session_id != 0) {
    state->session_id = ctx->session_id;
  }
  if (ctx->stream_id != 0) {
    state->next_stream_id = ctx->stream_id;
  }
  if (ctx->message_id != 0) {
    state->next_message_id = ctx->message_id;
  }

  if (ctx->ip[0] != '\0') {
    target_ip = ctx->ip;
  } else if (state->remote_ip[0] != '\0') {
    target_ip = state->remote_ip;
  }

  if (ctx->port != 0) {
    target_port = ctx->port;
  } else {
    target_port = state->remote_port;
  }

  return state->ctx->udp->send(state->socket_fd, target_ip, target_port, buf, len);
}

static int m7mux_recv(M7MuxState *state, M7MuxRecvContext *out) {
  if (!m7mux_listener_drain(state, 0u, out)) {
    return 0;
  }

  m7mux_fill_identity(state, &state->listener.ingress, out);
  return 1;
}
//clean up -- pseudo code.
static int m7mux_pump(M7MuxState *state, uint64_t now_ms) {
  (void)now_ms;

  if (!state->connected) {
    return 0;
  }

  timeout_ms = app.daemon2.connection.outbound_ready(&connection_state)
                   ? 0u
                   : time_until_ms(next_tick_at, now_ms);

  //re implementation of daemon2.runner
  //drain the socket. plain listener, maybe just a small wrap.
  while (listener.drain(listener, timeout_ms, &raw_data)) {
    demux.detect(&raw_data); //demux packet
    decode.normalize(&raw_data,&normal_data); //normalize it;
    session.ingest(&session_state, &normal_data); //extract the session
    stream.enqueue(&stream_state, &normal_data,&response_data); //stage for assembly
    //que acks if stream indicates it.
    if(response_data->ack)
      outbound.enqueue(%mux_state, &response_data);
    memset(&normal_data, 0, sizeof(normal_data));
    timeout_ms = 0u;
  }
  
  //construct streams , messages
  stream.pump(&stream_state);
  //sends any data queued;
  outbound.pump(&mux_state);
  //flush any timed out, or terminated sessions;
  session.pump(&mux_state);
  return 1;
}

static int m7mux_reply(M7MuxState *state, const M7MuxSendContext *ctx, const void *buf, size_t len) {
  return m7mux_send(state, ctx, buf, len);
}

static int m7mux_reply_to(M7MuxState *state, const M7MuxRecvContext *rx, const void *buf, size_t len) {
  M7MuxSendContext tx = {0};

  memset(&tx, 0, sizeof(tx));
  m7mux_copy_ip(tx.ip, sizeof(tx.ip), rx->ip);
  tx.port = rx->port;
  tx.session_id = rx->session_id;
  tx.message_id = rx->message_id;
  tx.stream_id = rx->stream_id;
  tx.flags = rx->flags;

  return m7mux_reply(state, &tx, buf, len);
}

static void m7mux_disconnect(M7MuxState *state) {
  if (state->owns_socket && state->socket_fd >= 0) {
    state->ctx->socket->close(state->socket_fd);
  }

  memset(state, 0, sizeof(*state));
  free(state);
}

static const M7MuxLib g_m7mux = {
  .init = m7mux_init,
  .set_context = m7mux_set_context,
  .shutdown = m7mux_shutdown,
  .register_adapter = m7mux_register_adapter,
  .unregister_adapter = m7mux_unregister_adapter,
  .register_demux = m7mux_register_demux,
  .unregister_demux = m7mux_unregister_demux,
  .connect_ip = m7mux_connect_ip,
  .connect_socket = m7mux_connect_socket,
  .send = m7mux_send,
  .recv = m7mux_recv,
  .pump = m7mux_pump,
  .reply = m7mux_reply,
  .reply_to = m7mux_reply_to,
  .disconnect = m7mux_disconnect
};

const M7MuxLib *get_lib_m7mux(void) {
  return &g_m7mux;
}
