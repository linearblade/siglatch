/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "job.h"

#include <stdlib.h>
#include <string.h>

#include "../app.h"
#include "../../../shared/knock/codec/user.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

#define APP_JOB_READY_QUEUE_CAPACITY 64u

static int app_job_init(void) {
  return 1;
}

static void app_job_shutdown(void) {
}

static void app_job_release_owned_buffer(uint8_t **buffer,
                                         size_t *len,
                                         size_t *cap) {
  if (!buffer) {
    return;
  }

  free(*buffer);
  *buffer = NULL;

  if (len) {
    *len = 0u;
  }

  if (cap) {
    *cap = 0u;
  }
}

static void app_job_release_payload(AppConnectionJob *job) {
  if (!job) {
    return;
  }

  app_job_release_owned_buffer(&job->request.payload_buffer,
                               &job->request.payload_len,
                               &job->request.payload_cap);
}

static void app_job_release_response(AppConnectionJob *job) {
  if (!job) {
    return;
  }

  app_job_release_owned_buffer(&job->response_buffer, &job->response_len, &job->response_cap);
}

static void app_job_release_job(AppConnectionJob *job) {
  if (!job) {
    return;
  }

  app_job_release_payload(job);
  app_job_release_response(job);
}

static size_t app_job_next_buffer_cap(size_t current_cap, size_t min_cap, size_t block_size) {
  size_t next_cap = current_cap;

  if (next_cap < block_size) {
    next_cap = block_size;
  }

  if (next_cap == 0u) {
    next_cap = block_size;
  }

  while (next_cap < min_cap) {
    if (next_cap > SIZE_MAX / 2u) {
      return 0u;
    }

    next_cap *= 2u;
  }

  return next_cap;
}

static int app_job_reserve_buffer(uint8_t **buffer,
                                  size_t *cap,
                                  size_t min_cap,
                                  size_t block_size) {
  uint8_t *next_buffer = NULL;
  size_t next_cap = 0u;

  if (!buffer || !cap) {
    return 0;
  }

  if (min_cap == 0u) {
    return 1;
  }

  if (*buffer && *cap >= min_cap) {
    return 1;
  }

  next_cap = app_job_next_buffer_cap(*cap, min_cap, block_size);
  if (next_cap == 0u) {
    return 0;
  }

  next_buffer = realloc(*buffer, next_cap);
  if (!next_buffer) {
    return 0;
  }

  *buffer = next_buffer;
  *cap = next_cap;
  return 1;
}

static int app_job_copy_payload(AppConnectionJob *job,
                                const uint8_t *payload,
                                size_t payload_len) {
  if (!job) {
    return 0;
  }

  if (payload_len > 0u && !payload) {
    return 0;
  }

  if (payload_len == 0u) {
    job->request.payload_len = 0u;
    return 1;
  }

  if (!app_job_reserve_buffer(&job->request.payload_buffer,
                              &job->request.payload_cap,
                              payload_len,
                              APP_JOB_PAYLOAD_BLOCK_SIZE)) {
    return 0;
  }

  memcpy(job->request.payload_buffer, payload, payload_len);
  job->request.payload_len = payload_len;
  return 1;
}

static int app_job_reserve_response(AppConnectionJob *job, size_t min_cap) {
  if (!job) {
    return 0;
  }

  return app_job_reserve_buffer(&job->response_buffer,
                                &job->response_cap,
                                min_cap,
                                APP_JOB_RESPONSE_BLOCK_SIZE);
}

static int app_job_load_from_normal(AppConnectionJob *job,
                                    const struct M7MuxRecvPacket *normal) {
  const M7MuxUserRecvData *user = NULL;

  if (!job || !normal) {
    return 0;
  }

  app_job_release_job(job);
  memset(job, 0, sizeof(*job));

  job->should_reply = normal->should_reply;
  job->available = 1;
  job->synthetic_session = normal->synthetic_session;
  job->wire_version = normal->wire_version;
  job->wire_form = normal->wire_form;
  job->session_id = normal->session_id;
  job->message_id = normal->message_id;
  job->stream_id = normal->stream_id;
  job->fragment_index = normal->fragment_index;
  job->fragment_count = normal->fragment_count;
  job->timestamp = normal->timestamp;
  memcpy(job->ip, normal->ip, sizeof(job->ip));
  job->ip[sizeof(job->ip) - 1] = '\0';
  job->client_port = normal->client_port;
  job->encrypted = normal->encrypted;
  job->wire_auth = normal->wire_auth;

  if (normal->wire_version == 0u) {
    job->request.user_id = 0u;
    job->request.action_id = 0u;
    job->request.challenge = 0u;
    memset(job->request.hmac, 0, sizeof(job->request.hmac));

    if (normal->raw_bytes_len > 0u) {
      if (!app_job_copy_payload(job, normal->raw_bytes, normal->raw_bytes_len)) {
        app_job_release_job(job);
        memset(job, 0, sizeof(*job));
        return 0;
      }
    }
  } else {
    user = normal->user;
    if (!user) {
      return 0;
    }

    job->request.user_id = user->user_id;
    job->request.action_id = user->action_id;
    job->request.challenge = user->challenge;
    memcpy(job->request.hmac, user->hmac, sizeof(job->request.hmac));

    if (user->payload_len > 0u) {
      if (!app_job_copy_payload(job, user->payload, user->payload_len)) {
        app_job_release_job(job);
        memset(job, 0, sizeof(*job));
        return 0;
      }
    }
  }

  return 1;
}

static int app_job_state_init(AppJobState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  return 1;
}

static void app_job_state_reset(AppJobState *state) {
  size_t i = 0;

  if (!state) {
    return;
  }

  for (i = 0; i < APP_JOB_READY_QUEUE_CAPACITY; ++i) {
    app_job_release_job(&state->ready_queue[i]);
  }

  memset(state, 0, sizeof(*state));
}

/*
 * Job storage is a simple ordered queue of delivered app units.
 *
 * The runner hands this module normalized packets that already carry transport
 * identity and ordered payload bytes. job.enqueue() materializes one owned job
 * from each normalized packet so later app code can drain work without
 * redoing transport framing.
 */
static int app_job_enqueue(AppJobState *state, const struct M7MuxRecvPacket *normal) {
  AppConnectionJob *slot = NULL;

  if (!state || !normal) {
    return 0;
  }

  if (state->ready_count >= APP_JOB_READY_QUEUE_CAPACITY) {
    return 0;
  }

  slot = &state->ready_queue[state->ready_tail];
  app_job_release_job(slot);
  memset(slot, 0, sizeof(*slot));

  if (!app_job_load_from_normal(slot, normal)) {
    return 0;
  }

  state->ready_tail = (state->ready_tail + 1u) % APP_JOB_READY_QUEUE_CAPACITY;
  state->ready_count++;

  return 1;
}

static int app_job_drain(AppJobState *state, AppConnectionJob *out_job) {
  AppConnectionJob *slot = NULL;

  if (!state || !out_job) {
    return 0;
  }

  if (state->ready_count == 0) {
    app_job_release_job(out_job);
    memset(out_job, 0, sizeof(*out_job));
    return 0;
  }

  slot = &state->ready_queue[state->ready_head];
  app_job_release_job(out_job);
  memset(out_job, 0, sizeof(*out_job));
  memcpy(out_job, slot, sizeof(*out_job));
  memset(slot, 0, sizeof(*slot));

  state->ready_head = (state->ready_head + 1u) % APP_JOB_READY_QUEUE_CAPACITY;
  state->ready_count--;

  return 1;
}

static int app_job_consume(AppRuntimeListenerState *listener,
                           AppConnectionJob *job,
                           SiglatchOpenSSLSession *session) {
  if (!app.daemon.payload.consume) {
    return 0;
  }

  return app.daemon.payload.consume(listener, job, session);
}

static void app_job_dispose(AppJobState *state, AppConnectionJob *job) {
  (void)state;

  if (!job) {
    return;
  }

  app_job_release_job(job);
  memset(job, 0, sizeof(*job));
}

static int app_job_flush_buffer(AppConnectionJob *job) {
  if (!job) {
    return 0;
  }

  app_job_release_job(job);
  memset(job, 0, sizeof(*job));
  return 1;
}

static const AppJobLib app_job_instance = {
  .init = app_job_init,
  .shutdown = app_job_shutdown,
  .state_init = app_job_state_init,
  .state_reset = app_job_state_reset,
  .enqueue = app_job_enqueue,
  .drain = app_job_drain,
  .consume = app_job_consume,
  .reserve_response = app_job_reserve_response,
  .dispose = app_job_dispose,
  .flush_buffer = app_job_flush_buffer
};

const AppJobLib *get_app_daemon_job_lib(void) {
  return &app_job_instance;
}
