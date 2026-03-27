/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "job.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../app.h"
#define APP_JOB_READY_QUEUE_CAPACITY 64u

static int app_job_init(void) {
  return 1;
}

static void app_job_shutdown(void) {
}

static int app_job_state_init(AppJobState *state) {
  if (!state) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  return 1;
}

static void app_job_state_reset(AppJobState *state) {
  if (!state) {
    return;
  }

  memset(state, 0, sizeof(*state));
}

static AppConnectionJob *app_job_tail_slot(AppJobState *state) {
  if (!state || state->ready_count == 0) {
    return NULL;
  }

  return &state->ready_queue[(state->ready_tail + APP_JOB_READY_QUEUE_CAPACITY - 1u) %
                             APP_JOB_READY_QUEUE_CAPACITY];
}

/*
 * Job storage is a simple ordered queue of complete app units.
 *
 * The runner hands this module normalized units that already carry transport
 * identity and ordered payload bytes. job.enqueue() keeps that order intact
 * so later app code can drain work without redoing transport reassembly.
 */
static int app_job_enqueue(AppJobState *state, AppConnectionJob *job) {
  AppConnectionJob *slot = NULL;
  AppConnectionJob *tail = NULL;

  if (!state || !job) {
    return 0;
  }

  if (job->payload_len > sizeof(job->payload_buffer) ||
      job->response_len > sizeof(job->response_buffer)) {
    return 0;
  }

  tail = app_job_tail_slot(state);
  if (tail) {
    if (tail->payload_len + job->payload_len > sizeof(tail->payload_buffer)) {
      return 0;
    }

    memcpy(tail->payload_buffer + tail->payload_len, job->payload_buffer, job->payload_len);
    tail->payload_len += job->payload_len;
    tail->complete |= job->complete;
    tail->should_reply |= job->should_reply;
    tail->synthetic_session = job->synthetic_session;
    tail->wire_version = job->wire_version;
    tail->wire_form = job->wire_form;
    tail->session_id = job->session_id;
    tail->message_id = job->message_id;
    tail->stream_id = job->stream_id;
    tail->fragment_index = job->fragment_index;
    tail->fragment_count = job->fragment_count;
    tail->timestamp = job->timestamp;
    tail->user_id = job->user_id;
    tail->action_id = job->action_id;
    tail->challenge = job->challenge;
    memcpy(tail->hmac, job->hmac, sizeof(tail->hmac));
    memcpy(tail->ip, job->ip, sizeof(tail->ip));
    tail->ip[sizeof(tail->ip) - 1] = '\0';
    tail->client_port = job->client_port;
    tail->encrypted = job->encrypted;
    memset(tail->response_buffer, 0, sizeof(tail->response_buffer));
    tail->response_len = 0;
    return 1;
  }

  if (state->ready_count >= APP_JOB_READY_QUEUE_CAPACITY) {
    return 0;
  }

  slot = &state->ready_queue[state->ready_tail];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot, job, sizeof(*slot));
  slot->ip[sizeof(slot->ip) - 1] = '\0';

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
    memset(out_job, 0, sizeof(*out_job));
    return 0;
  }

  slot = &state->ready_queue[state->ready_head];
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
  if (!app.daemon3.payload.consume) {
    return 0;
  }

  return app.daemon3.payload.consume(listener, job, session);
}

static void app_job_dispose(AppJobState *state, AppConnectionJob *job) {
  (void)state;
  (void)job;
}

static int app_job_flush_buffer(AppConnectionJob *job) {
  if (!job) {
    return 0;
  }

  memset(job->payload_buffer, 0, sizeof(job->payload_buffer));
  memset(job->response_buffer, 0, sizeof(job->response_buffer));
  job->payload_len = 0;
  job->response_len = 0;
  job->complete = 0;
  job->should_reply = 0;
  job->synthetic_session = 0;
  job->fragment_index = 0;
  job->fragment_count = 0;
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
  .dispose = app_job_dispose,
  .flush_buffer = app_job_flush_buffer
};

const AppJobLib *get_app_daemon3_job_lib(void) {
  return &app_job_instance;
}
