/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "stream.h"

#include <string.h>

void m7mux_stream_release_user(M7MuxStreamState *state, const M7MuxRecvPacket *packet);
static int m7mux_stream_copy_user(M7MuxStreamState *state,
                                  const M7MuxRecvPacket *packet,
                                  M7MuxUserRecvData *dst,
                                  const M7MuxUserRecvData *src);

static int m7mux_stream_init(void) {
  return 1;
}

static void m7mux_stream_shutdown(void) {
}

static int m7mux_stream_state_init(M7MuxStreamState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  state->next_message_id = 1u;
  return 1;
}

static void m7mux_stream_state_reset(M7MuxStreamState *state) {
  size_t i = 0;
  const M7MuxNormalizeAdapterLib *adapter_lib = NULL;

  if (!state) {
    return;
  }

  adapter_lib = state->adapter_lib;
  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    m7mux_stream_release_user(state, &state->ready_queue[i]);
  }

  memset(state, 0, sizeof(*state));
  state->adapter_lib = adapter_lib;
  state->next_message_id = 1u;
}

static int m7mux_stream_has_pending(const M7MuxStreamState *state) {
  if (!state) {
    return 0;
  }

  return state->ready_count > 0u;
}

static int m7mux_stream_is_expired(const M7MuxRecvPacket *slot, uint64_t now_ms) {
  if (!slot || slot->session_id == 0u || slot->complete) {
    return 0;
  }

  if (slot->received_ms == 0u) {
    return 1;
  }

  if (now_ms < slot->received_ms) {
    return 0;
  }

  return (now_ms - slot->received_ms) >= M7MUX_STREAM_EXPIRE_AFTER_MS;
}

void m7mux_stream_release_user(M7MuxStreamState *state, const M7MuxRecvPacket *packet) {
  const M7MuxNormalizeAdapter *adapter = NULL;

  if (!state || !state->adapter_lib || !state->adapter_lib->lookup_adapter_wire_version ||
      !packet || !packet->user) {
    return;
  }

  adapter = state->adapter_lib->lookup_adapter_wire_version(packet->wire_version);

  if (!adapter || !adapter->free_user_recv_data) {
    return;
  }

  adapter->free_user_recv_data((M7MuxUserRecvData *)packet->user);
}

static int m7mux_stream_copy_user(M7MuxStreamState *state,
                                  const M7MuxRecvPacket *packet,
                                  M7MuxUserRecvData *dst,
                                  const M7MuxUserRecvData *src) {
  const M7MuxNormalizeAdapter *adapter = NULL;

  if (!state || !state->adapter_lib || !state->adapter_lib->lookup_adapter_wire_version ||
      !packet || !dst || !src) {
    return 0;
  }

  adapter = state->adapter_lib->lookup_adapter_wire_version(packet->wire_version);

  if (!adapter || !adapter->copy_user_recv_data) {
    return 0;
  }

  return adapter->copy_user_recv_data(dst, src);
}

static int m7mux_stream_ingest(M7MuxStreamState *state, const M7MuxRecvPacket *normal) {
  M7MuxRecvPacket *slot = NULL;
  size_t i = 0;
  int final_fragment = 0;

  if (!state || !normal || normal->session_id == 0) {
    return 0;
  }

  if (normal->fragment_count == 0u) {
    final_fragment = 1;
  } else {
    final_fragment = normal->complete ||
                     ((normal->fragment_index + 1u) >= normal->fragment_count);
  }

  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    if (state->ready_queue[i].session_id == normal->session_id &&
        state->ready_queue[i].stream_id == normal->stream_id &&
        state->ready_queue[i].message_id == normal->message_id) {
      slot = &state->ready_queue[i];
      break;
    }
  }

  if (!slot) {
    for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
      if (state->ready_queue[i].session_id == 0u) {
        slot = &state->ready_queue[i];
        break;
      }
    }
  }

  if (!slot) {
    return 0;
  }

  if (slot->session_id == 0u) {
    if (normal->message_id == 0u) {
      if (!final_fragment) {
        return 0;
      }

      memcpy(slot, normal, sizeof(*slot));
      slot->message_id = state->next_message_id++;
      if (slot->message_id >= state->next_message_id) {
        state->next_message_id = slot->message_id + 1u;
      }
    } else {
      memcpy(slot, normal, sizeof(*slot));
    }

    slot->complete = final_fragment ? 1 : 0;
    if (slot->complete) {
      state->ready_count++;
    }
    return 1;
  }

  if (slot->complete) {
    return 0;
  }

  return 0;
}

static int m7mux_stream_drain(M7MuxStreamState *state, M7MuxRecvPacket *out_normal) {
  size_t i = 0;
  M7MuxRecvPacket *slot = NULL;
  const M7MuxUserRecvData *caller_user = NULL;

  if (!state || !out_normal) {
    return 0;
  }

  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    if (state->ready_queue[i].session_id != 0u && state->ready_queue[i].complete) {
      slot = &state->ready_queue[i];
      break;
    }
  }

  if (!slot) {
    memset(out_normal, 0, sizeof(*out_normal));
    return 0;
  }

  caller_user = out_normal->user;

  if (slot->user && !caller_user) {
    return 0;
  }

  if (caller_user && slot->user) {
    if (!m7mux_stream_copy_user(state,
                                slot,
                                (M7MuxUserRecvData *)caller_user,
                                (const M7MuxUserRecvData *)slot->user)) {
      return 0;
    }
  }

  memcpy(out_normal, slot, sizeof(*out_normal));

  out_normal->user = slot->user ? caller_user : NULL;

  m7mux_stream_release_user(state, slot);

  memset(slot, 0, sizeof(*slot));

  if (state->ready_count > 0u) {
    state->ready_count--;
  }

  return 1;
}

static int m7mux_stream_expire(M7MuxStreamState *state, uint64_t now_ms) {
  size_t i = 0;
  int expired = 0;

  if (!state) {
    return 0;
  }

  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    M7MuxRecvPacket *slot = &state->ready_queue[i];

    if (!m7mux_stream_is_expired(slot, now_ms)) {
      continue;
    }

    m7mux_stream_release_user(state, slot);
    memset(slot, 0, sizeof(*slot));
    if (state->ready_count > 0u) {
      state->ready_count--;
    }
    expired++;
  }

  return expired;
}

static int m7mux_stream_pump(M7MuxStreamState *state, uint64_t now_ms) {
  return m7mux_stream_expire(state, now_ms);
}

static const M7MuxStreamLib _instance = {
  .init = m7mux_stream_init,
  .shutdown = m7mux_stream_shutdown,
  .state_init = m7mux_stream_state_init,
  .state_reset = m7mux_stream_state_reset,
  .has_pending = m7mux_stream_has_pending,
  .ingest = m7mux_stream_ingest,
  .drain = m7mux_stream_drain,
  .expire = m7mux_stream_expire,
  .pump = m7mux_stream_pump
};

const M7MuxStreamLib *get_protocol_udp_m7mux_stream_lib(void) {
  return &_instance;
}
