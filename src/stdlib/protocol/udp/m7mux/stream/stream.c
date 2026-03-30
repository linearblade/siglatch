/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "stream.h"

#include <string.h>

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
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
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
      slot->user.message_id = slot->message_id;
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

  if (slot->user.payload_len + normal->user.payload_len > sizeof(slot->user.payload)) {
    return 0;
  }

  if (normal->user.payload_len > 0u) {
    memcpy(slot->user.payload + slot->user.payload_len,
           normal->user.payload,
           normal->user.payload_len);
    slot->user.payload_len += normal->user.payload_len;
  }

  slot->fragment_index = normal->fragment_index;
  if (normal->fragment_count > slot->fragment_count) {
    slot->fragment_count = normal->fragment_count;
  }
  slot->complete = final_fragment ? 1 : 0;
  slot->should_reply |= normal->should_reply;
  slot->wire_version = normal->wire_version;
  slot->wire_form = normal->wire_form;
  slot->received_ms = normal->received_ms;
  slot->timestamp = normal->timestamp;
  memcpy(slot->label, normal->label, sizeof(slot->label));
  slot->user.complete = slot->complete;
  slot->user.fragment_index = slot->fragment_index;
  slot->user.fragment_count = slot->fragment_count;
  slot->user.timestamp = slot->timestamp;
  slot->user.wire_version = slot->wire_version;
  slot->user.wire_form = slot->wire_form;
  memcpy(slot->user.ip, normal->user.ip, sizeof(slot->user.ip));
  slot->user.client_port = normal->user.client_port;
  slot->user.encrypted = normal->user.encrypted;
  slot->user.wire_auth = normal->user.wire_auth;

  if (slot->complete) {
    state->ready_count++;
  }

  return 1;
}

static int m7mux_stream_drain(M7MuxStreamState *state, M7MuxRecvPacket *out_normal) {
  size_t i = 0;
  M7MuxRecvPacket *slot = NULL;

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

  memcpy(out_normal, slot, sizeof(*out_normal));
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

    memset(slot, 0, sizeof(*slot));
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
