/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "stream.h"

#include <stdio.h>
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
}

static int m7mux_stream_has_pending(const M7MuxStreamState *state) {
  if (!state) {
    return 0;
  }

  return state->ready_count > 0u;
}

static int m7mux_stream_is_expired(const M7MuxRecvPacket *slot, uint64_t now_ms) {
  if (!slot || slot->session_id == 0u) {
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

static M7MuxStreamSessionTracker *m7mux_stream_find_session_tracker(M7MuxStreamState *state,
                                                                   uint64_t session_id,
                                                                   int create) {
  size_t i = 0;
  M7MuxStreamSessionTracker *free_slot = NULL;

  if (!state || session_id == 0u) {
    return NULL;
  }

  for (i = 0; i < M7MUX_STREAM_SESSION_TRACKER_CAPACITY; ++i) {
    if (state->session_trackers[i].active &&
        state->session_trackers[i].session_id == session_id) {
      return &state->session_trackers[i];
    }

    if (create && !free_slot && !state->session_trackers[i].active) {
      free_slot = &state->session_trackers[i];
    }
  }

  if (!create || !free_slot) {
    return NULL;
  }

  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->active = 1;
  free_slot->session_id = session_id;
  free_slot->next_stream_id = 1u;
  return free_slot;
}

static M7MuxStreamMessageTracker *m7mux_stream_find_message_tracker(M7MuxStreamSessionTracker *session,
                                                                    uint32_t stream_id,
                                                                    int create) {
  size_t i = 0;
  M7MuxStreamMessageTracker *free_slot = NULL;

  if (!session || stream_id == 0u) {
    return NULL;
  }

  for (i = 0; i < M7MUX_STREAM_TRACKER_CAPACITY; ++i) {
    if (session->stream_trackers[i].active &&
        session->stream_trackers[i].stream_id == stream_id) {
      return &session->stream_trackers[i];
    }

    if (create && !free_slot && !session->stream_trackers[i].active) {
      free_slot = &session->stream_trackers[i];
    }
  }

  if (!create || !free_slot) {
    return NULL;
  }

  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->active = 1;
  free_slot->stream_id = stream_id;
  free_slot->next_message_id = 1u;
  return free_slot;
}

static int m7mux_stream_message_tracker_begin(M7MuxStreamMessageTracker *tracker,
                                              const M7MuxRecvPacket *packet) {
  uint32_t fragment_count = 0u;

  if (!tracker || !packet || packet->message_id == 0u) {
    return 0;
  }

  fragment_count = packet->fragment_count;
  if (fragment_count == 0u) {
    fragment_count = 1u;
  }

  /*
   * Singular packets are not part of a multi-fragment in-flight chain.
   * Let them queue without claiming exclusive stream state.
   */
  if (fragment_count <= 1u) {
    return 1;
  }

  if (tracker->message_id == 0u) {
    tracker->message_id = packet->message_id;
    tracker->next_fragment_index = 0u;
    tracker->fragment_count = fragment_count;
    return 1;
  }

  if (tracker->message_id == packet->message_id) {
    if (tracker->fragment_count == 0u) {
      tracker->fragment_count = fragment_count;
    }
    return 1;
  }

  if (tracker->next_fragment_index >= tracker->fragment_count) {
    tracker->message_id = packet->message_id;
    tracker->next_fragment_index = 0u;
    tracker->fragment_count = fragment_count;
    return 1;
  }

  return 0;
}

static int m7mux_stream_packet_is_deliverable(M7MuxStreamState *state,
                                              const M7MuxRecvPacket *packet) {
  M7MuxStreamSessionTracker *session_tracker = NULL;
  M7MuxStreamMessageTracker *message_tracker = NULL;

  if (!state || !packet || packet->session_id == 0u || packet->stream_id == 0u) {
    return 0;
  }

  session_tracker = m7mux_stream_find_session_tracker(state, packet->session_id, 0);
  if (!session_tracker) {
    return 0;
  }

  if (packet->fragment_count == 0u || packet->fragment_count == 1u) {
    return packet->fragment_index == 0u;
  }

  message_tracker = m7mux_stream_find_message_tracker(session_tracker, packet->stream_id, 0);
  if (!message_tracker || message_tracker->message_id == 0u) {
    return 0;
  }

  if (packet->message_id != message_tracker->message_id) {
    return 0;
  }

  return packet->fragment_index == message_tracker->next_fragment_index;
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
  M7MuxRecvPacket packet = {0};
  M7MuxRecvPacket *slot = NULL;
  M7MuxStreamSessionTracker *session_tracker = NULL;
  M7MuxStreamMessageTracker *message_tracker = NULL;
  size_t i = 0;
  int final_fragment = 0;

  if (!state || !normal || normal->session_id == 0u) {
    return 0;
  }

  packet = *normal;

  session_tracker = m7mux_stream_find_session_tracker(state, packet.session_id, 1);
  if (!session_tracker) {
    return 0;
  }

  if (packet.stream_id == 0u) {
    packet.stream_id = session_tracker->next_stream_id++;
    if (packet.stream_id >= session_tracker->next_stream_id) {
      session_tracker->next_stream_id = packet.stream_id + 1u;
    }
  } else if (packet.stream_id >= session_tracker->next_stream_id) {
    session_tracker->next_stream_id = packet.stream_id + 1u;
  }

  message_tracker = m7mux_stream_find_message_tracker(session_tracker, packet.stream_id, 1);
  if (!message_tracker) {
    return 0;
  }

  if (packet.message_id == 0u) {
    packet.message_id = message_tracker->next_message_id++;
    if (packet.message_id >= message_tracker->next_message_id) {
      message_tracker->next_message_id = packet.message_id + 1u;
    }
  } else if (packet.message_id >= message_tracker->next_message_id) {
    message_tracker->next_message_id = packet.message_id + 1u;
  }

  if (!m7mux_stream_message_tracker_begin(message_tracker, &packet)) {
    return 0;
  }

  if (packet.fragment_count == 0u) {
    final_fragment = 1;
  } else {
    final_fragment = ((packet.fragment_index + 1u) >= packet.fragment_count);
  }

  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    if (state->ready_queue[i].session_id == packet.session_id &&
        state->ready_queue[i].stream_id == packet.stream_id &&
        state->ready_queue[i].message_id == packet.message_id &&
        state->ready_queue[i].fragment_index == packet.fragment_index) {
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

  if (slot->session_id != 0u) {
    printf("[m7mux.stream] fragment collision session=%llu stream=%u message=%llu fragment=%u\n",
           (unsigned long long)packet.session_id,
           (unsigned)packet.stream_id,
           (unsigned long long)packet.message_id,
           (unsigned)packet.fragment_index);
    fflush(stdout);
    return 0;
  }

  m7mux_stream_release_user(state, slot);
  memcpy(slot, &packet, sizeof(*slot));
  slot->complete = final_fragment ? 1 : 0;
  state->ready_count++;
  fprintf(stderr,
          "[m7mux.stream] queued session=%llu stream=%u message=%llu fragment=%u/%u final=%d\n",
          (unsigned long long)slot->session_id,
          (unsigned)slot->stream_id,
          (unsigned long long)slot->message_id,
          (unsigned)(slot->fragment_index + 1u),
          (unsigned)slot->fragment_count,
          slot->complete ? 1 : 0);
  return 1;
}

static int m7mux_stream_drain(M7MuxStreamState *state, M7MuxRecvPacket *out_normal) {
  size_t i = 0;
  M7MuxRecvPacket *slot = NULL;
  const M7MuxUserRecvData *caller_user = NULL;

  if (!state || !out_normal) {
    return 0;
  }

  for (i = 0; i < M7MUX_STREAM_READY_QUEUE_CAPACITY; ++i) {
    if (state->ready_queue[i].session_id != 0u &&
        m7mux_stream_packet_is_deliverable(state, &state->ready_queue[i])) {
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

  if (slot->fragment_count > 1u) {
    M7MuxStreamSessionTracker *session_tracker = NULL;
    M7MuxStreamMessageTracker *message_tracker = NULL;

    session_tracker = m7mux_stream_find_session_tracker(state, slot->session_id, 0);
    if (session_tracker) {
      message_tracker = m7mux_stream_find_message_tracker(session_tracker, slot->stream_id, 0);
      if (message_tracker && message_tracker->message_id == slot->message_id) {
        if (message_tracker->next_fragment_index < UINT32_MAX) {
          message_tracker->next_fragment_index++;
        }

        if (message_tracker->fragment_count == 0u ||
            message_tracker->next_fragment_index >= message_tracker->fragment_count) {
          message_tracker->message_id = 0u;
          message_tracker->next_fragment_index = 0u;
          message_tracker->fragment_count = 0u;
        }
      }
    }
  }

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
