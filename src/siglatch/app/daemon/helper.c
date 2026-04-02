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

static int app_daemon_copy_job_to_knock_packet(const AppConnectionJob *job,
                                                KnockPacket *out_pkt) {
  if (!job || !out_pkt) {
    return 0;
  }

  if ((job->request.payload_len > 0u && !job->request.payload_buffer) ||
      job->request.payload_len > sizeof(out_pkt->payload)) {
    return 0;
  }

  memset(out_pkt, 0, sizeof(*out_pkt));

  /*
   * //$fixup - legacy shim to keep older request-side helpers working while
   * // they still depend on KnockPacket. Payload sizing will need repair once
   * // the last packet-shaped consumers are removed.
   *
   * The current app-side consume path still speaks the legacy flat knock
   * packet contract. The listener normalizer gives us versioned transport
   * metadata, but the app semantics are still expressed through v1 fields.
   */
  out_pkt->version = 1u;
  out_pkt->timestamp = job->timestamp;
  out_pkt->user_id = job->request.user_id;
  out_pkt->action_id = job->request.action_id;
  out_pkt->challenge = job->request.challenge;
  memcpy(out_pkt->hmac, job->request.hmac, sizeof(out_pkt->hmac));
  out_pkt->payload_len = (uint16_t)job->request.payload_len;

  if (job->request.payload_len > 0u) {
    memcpy(out_pkt->payload, job->request.payload_buffer, job->request.payload_len);
  }

  return 1;
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
  out_send->message_id = job->message_id;
  out_send->stream_id = job->stream_id;
  out_send->fragment_index = job->fragment_index;
  out_send->fragment_count = job->fragment_count;
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
  .copy_job_to_knock_packet = app_daemon_copy_job_to_knock_packet,
  .copy_job_reply_to_send = app_daemon_copy_job_reply_to_send,
  .time_until_ms = app_daemon_time_until_ms
};

const AppDaemonHelperLib *get_app_daemon_helper_lib(void) {
  return &app_daemon_helper_instance;
}
