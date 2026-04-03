/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "helper.h"

#include <stdint.h>
#include <string.h>

#include "../app.h"
#include "../../../shared/knock/response.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

static int app_daemon_helper_init(void) {
  return 1;
}

static void app_daemon_helper_shutdown(void) {
}

static int app_daemon_copy_job_reply_to_send(const AppConnectionJob *job,
                                              M7MuxSendPacket *out_send,
                                              M7MuxUserSendData *out_user) {
  if (!job || !out_send || !out_user) {
    return 0;
  }

  if ((job->response_len > 0u && !job->response_buffer) ||
      job->response_len > sizeof(out_user->payload)) {
    return 0;
  }

  memset(out_send, 0, sizeof(*out_send));
  memset(out_user, 0, sizeof(*out_user));

  out_send->trace_id = 0u;
  memcpy(out_send->label, "daemon", sizeof("daemon"));
  out_send->wire_version = job->wire_version;
  out_send->wire_form = job->wire_form;
  out_send->received_ms = job->timestamp;
  out_send->session_id = job->session_id;
  /*
   * Keep reply packets distinct in the transport queue.
   * The request tuple may be shared by multiple fragment jobs, so reply
   * message ids are offset by the inbound fragment index.
   */
  out_send->message_id = job->message_id + (uint64_t)job->fragment_index;
  out_send->stream_id = job->stream_id;
  /*
   * Replies are singular packets for now.
   * Fragment metadata belongs to the inbound request path and should not be
   * inherited by response envelopes.
   */
  out_send->fragment_index = 0u;
  out_send->fragment_count = 1u;
  out_send->timestamp = job->timestamp;
  memcpy(out_send->ip, job->ip, sizeof(out_send->ip));
  out_send->ip[sizeof(out_send->ip) - 1] = '\0';
  out_send->client_port = job->client_port;
  out_send->encrypted = job->encrypted;
  out_send->wire_auth = job->wire_auth;

  out_user->user_id = job->request.user_id;
  out_user->action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  out_user->challenge = job->request.challenge;
  memcpy(out_user->hmac, job->request.hmac, sizeof(out_user->hmac));
  out_user->payload_len = job->response_len;
  if (job->response_len > 0u) {
    memcpy(out_user->payload, job->response_buffer, job->response_len);
  }
  out_send->user = out_user;
  return 1;
}

static uint64_t app_daemon_time_until_ms(uint64_t next_tick_at, uint64_t now_ms) {
  if (next_tick_at <= now_ms) {
    return 0;
  }

  return next_tick_at - now_ms;
}

static const AppDaemonHelperLib app_daemon_helper_instance = {
  .init = app_daemon_helper_init,
  .shutdown = app_daemon_helper_shutdown,
  .copy_job_reply_to_send = app_daemon_copy_job_reply_to_send,
  .time_until_ms = app_daemon_time_until_ms
};

const AppDaemonHelperLib *get_app_daemon_helper_lib(void) {
  return &app_daemon_helper_instance;
}
