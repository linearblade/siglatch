/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "session.h"

#include <stdio.h>
#include <string.h>

#include "../../../../../siglatch/lib.h"

static M7MuxSession *m7mux_session_find(M7MuxSessionState *state,
                                        uint64_t session_id) {
  size_t i = 0;

  if (!state || session_id == 0) {
    return NULL;
  }

  for (i = 0; i < M7MUX_SESSION_SESSION_CAPACITY; ++i) {
    if (state->sessions[i].active &&
        state->sessions[i].session_id == session_id) {
      return &state->sessions[i];
    }
  }

  return NULL;
}

static M7MuxSession *m7mux_session_find_by_client_session(M7MuxSessionState *state,
                                                          uint64_t client_session_id,
                                                          uint32_t wire_version,
                                                          uint8_t wire_form) {
  size_t i = 0;

  if (!state || client_session_id == 0u) {
    return NULL;
  }

  for (i = 0; i < M7MUX_SESSION_SESSION_CAPACITY; ++i) {
    if (!state->sessions[i].active) {
      continue;
    }

    if (state->sessions[i].client_session_id != client_session_id) {
      continue;
    }

    if (state->sessions[i].wire_version != wire_version) {
      continue;
    }

    if (state->sessions[i].wire_form != wire_form) {
      continue;
    }

    return &state->sessions[i];
  }

  return NULL;
}

static M7MuxSession *m7mux_session_find_raw_by_ip(M7MuxSessionState *state,
                                                  const char *ip) {
  size_t i = 0;

  if (!state || !ip || ip[0] == '\0') {
    return NULL;
  }

  for (i = 0; i < M7MUX_SESSION_SESSION_CAPACITY; ++i) {
    if (!state->sessions[i].active) {
      continue;
    }

    if (state->sessions[i].wire_version != 0u) {
      continue;
    }

    if (strncmp(state->sessions[i].ip, ip, sizeof(state->sessions[i].ip)) != 0) {
      continue;
    }

    return &state->sessions[i];
  }

  return NULL;
}

static void m7mux_session_touch(M7MuxSession *session, uint64_t now_ms) {
  if (!session) {
    return;
  }

  session->last_active_ms = now_ms;
  session->expires_at_ms = now_ms + M7MUX_SESSION_SESSION_TIMEOUT_MS;
}

static void m7mux_session_clear(M7MuxSessionState *state,
                                M7MuxSession *session) {
  if (!state || !session || !session->active) {
    return;
  }

  memset(session, 0, sizeof(*session));

  if (state->session_count > 0) {
    state->session_count--;
  }
}

static int m7mux_session_register(M7MuxSessionState *state,
                                           const M7MuxControl *control,
                                           M7MuxRecvPacket *normal,
                                           M7MuxSession **out_session) {
  size_t i = 0;
  int client_owned_session = 0;
  M7MuxSession *session = NULL;

  if (!state || !normal || !out_session) {
    return 0;
  }

  *out_session = NULL;
  client_owned_session = (control && control->session_by_client != 0u);

  if (client_owned_session) {
    session = m7mux_session_find_by_client_session(state,
                                                   normal->session_id,
                                                   normal->wire_version,
                                                   normal->wire_form);
    if (session) {
      session->wire_version = normal->wire_version;
      session->wire_form = normal->wire_form;
      memcpy(session->ip, normal->ip, sizeof(session->ip));
      session->ip[sizeof(session->ip) - 1] = '\0';
      session->client_port = normal->client_port;
      session->encrypted = normal->encrypted;
      if (normal->session_id != session->session_id) {
        fprintf(stderr,
                "[m7mux.session] client session=%llu mapped to server session=%llu\n",
                (unsigned long long)normal->session_id,
                (unsigned long long)session->session_id);
      }
      normal->session_id = session->session_id;
      *out_session = session;
      return 1;
    }
  }

  if (!client_owned_session && normal->session_id != 0) {
    *out_session = m7mux_session_find(state, normal->session_id);
    if (*out_session) {
      (*out_session)->wire_version = normal->wire_version;
      (*out_session)->wire_form = normal->wire_form;
      memcpy((*out_session)->ip, normal->ip, sizeof((*out_session)->ip));
      (*out_session)->ip[sizeof((*out_session)->ip) - 1] = '\0';
      (*out_session)->client_port = normal->client_port;
      (*out_session)->encrypted = normal->encrypted;
      return 1;
    }
  }

  if (normal->wire_version == 0u) {
    *out_session = m7mux_session_find_raw_by_ip(state, normal->ip);
    if (*out_session) {
      (*out_session)->client_port = normal->client_port;
      (*out_session)->encrypted = normal->encrypted;
      (*out_session)->wire_version = normal->wire_version;
      (*out_session)->wire_form = normal->wire_form;
      return 1;
    }
  }

  for (i = 0; i < M7MUX_SESSION_SESSION_CAPACITY; ++i) {
    if (!state->sessions[i].active) {
      memset(&state->sessions[i], 0, sizeof(state->sessions[i]));
      if (client_owned_session) {
        state->sessions[i].session_id = state->next_session_id++;
        state->sessions[i].client_session_id = normal->session_id != 0u
                                                   ? normal->session_id
                                                   : state->sessions[i].session_id;
        normal->session_id = state->sessions[i].session_id;
        if (normal->session_id != state->sessions[i].client_session_id) {
          fprintf(stderr,
                  "[m7mux.session] client session=%llu mapped to server session=%llu\n",
                  (unsigned long long)state->sessions[i].client_session_id,
                  (unsigned long long)state->sessions[i].session_id);
        }
      } else {
        state->sessions[i].session_id = normal->session_id != 0
                                            ? normal->session_id
                                            : state->next_session_id++;
      }
      if (state->sessions[i].session_id >= state->next_session_id) {
        state->next_session_id = state->sessions[i].session_id + 1u;
      }
      memcpy(state->sessions[i].ip, normal->ip, sizeof(state->sessions[i].ip));
      state->sessions[i].ip[sizeof(state->sessions[i].ip) - 1] = '\0';
      state->sessions[i].client_port = normal->client_port;
      state->sessions[i].encrypted = normal->encrypted;
      state->sessions[i].wire_version = normal->wire_version;
      state->sessions[i].wire_form = normal->wire_form;
      if (!client_owned_session) {
        state->sessions[i].client_session_id = 0u;
      }
      state->sessions[i].active = 1;
      state->session_count++;
      *out_session = &state->sessions[i];
      return 1;
    }
  }

  return 0;
}


static int m7mux_session_init(void) {
  return 1;
}

static void m7mux_session_shutdown(void) {
}


static int m7mux_session_state_init(M7MuxSessionState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  state->next_session_id = 1u;
  return 1;
}


static void m7mux_session_state_reset(M7MuxSessionState *state) {
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
  state->next_session_id = 1u;
}



/*
 * Session intake only.
 *
 * This layer is responsible for identifying or creating the session anchor
 * for an incoming normalized unit. It does not build jobs, append fragments,
 * or decide readiness. That happens in app.daemon2.job.
 *
 * When the incoming unit has no session id yet, the connection layer creates
 * one so single-packet traffic can still be tracked and later cleaned up.
 */

static int m7mux_session_ingest(M7MuxSessionState *state,
                                const M7MuxControl *control,
                                M7MuxRecvPacket *normal) {
  M7MuxSession *session = NULL;
  int synthetic_session = 0;
  int client_owned_session = 0;

  if (!state || !normal) {
    return 0;
  }

  client_owned_session = (control && control->session_by_client != 0u);
  synthetic_session = (normal->session_id == 0);

  if (!m7mux_session_register(state, control, normal, &session)) {
    return 0;
  }

  if (synthetic_session && session && !client_owned_session) {
    normal->session_id = session->session_id;
  }

  if (client_owned_session && session) {
    normal->session_id = session->session_id;
  }

  normal->synthetic_session = synthetic_session;

  m7mux_session_touch(session, lib.time.monotonic_ms());
  return 1;
}


static int m7mux_session_release(M7MuxSessionState *state,
                                 uint64_t session_id) {
  M7MuxSession *session = NULL;

  if (!state || session_id == 0) {
    return 0;
  }

  session = m7mux_session_find(state, session_id);
  if (!session) {
    return 0;
  }

  m7mux_session_clear(state, session);
  return 1;
}

static int m7mux_session_expire(M7MuxSessionState *state, uint64_t now_ms) {
  size_t i = 0;
  int expired = 0;

  if (!state) {
    return 0;
  }

  for (i = 0; i < M7MUX_SESSION_SESSION_CAPACITY; ++i) {
    if (!state->sessions[i].active) {
      continue;
    }

    if (state->sessions[i].expires_at_ms == 0 ||
        state->sessions[i].expires_at_ms > now_ms) {
      continue;
    }

    m7mux_session_clear(state, &state->sessions[i]);
    expired++;
  }

  return expired;
}

static const M7MuxSessionLib _instance = {
  .init        = m7mux_session_init,
  .shutdown    = m7mux_session_shutdown,
  .state_init  = m7mux_session_state_init,
  .state_reset = m7mux_session_state_reset,
  .ingest      = m7mux_session_ingest,
  .release     = m7mux_session_release,
  .expire      = m7mux_session_expire,
};

const M7MuxSessionLib *get_protocol_udp_m7mux_session_lib(void) {
  return &_instance;
}
