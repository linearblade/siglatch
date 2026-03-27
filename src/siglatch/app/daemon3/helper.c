/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "helper.h"

#include <stdint.h>
#include <string.h>

#include "../../../shared/knock/response.h"

static int app_daemon3_helper_init(void) {
  return 1;
}

static void app_daemon3_helper_shutdown(void) {
}

static int app_daemon3_copy_job_to_knock_packet(const AppConnectionJob *job,
                                                KnockPacket *out_pkt) {
  if (!job || !out_pkt) {
    return 0;
  }

  if (job->payload_len > sizeof(out_pkt->payload)) {
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
  out_pkt->user_id = job->user_id;
  out_pkt->action_id = job->action_id;
  out_pkt->challenge = job->challenge;
  memcpy(out_pkt->hmac, job->hmac, sizeof(out_pkt->hmac));
  out_pkt->payload_len = (uint16_t)job->payload_len;

  if (job->payload_len > 0u) {
    memcpy(out_pkt->payload, job->payload_buffer, job->payload_len);
  }

  return 1;
}

static void app_daemon3_copy_mux_ingress_to_job(const M7MuxNormalizedPacket *normal,
                                                AppConnectionJob *out_job) {
  if (!normal || !out_job) {
    return;
  }

  memset(out_job, 0, sizeof(*out_job));
  out_job->complete = normal->complete;
  out_job->should_reply = normal->should_reply;
  out_job->synthetic_session = normal->synthetic_session;
  out_job->wire_version = normal->wire_version;
  out_job->wire_form = normal->wire_form;
  out_job->session_id = normal->session_id;
  out_job->message_id = normal->message_id;
  out_job->stream_id = normal->stream_id;
  out_job->fragment_index = normal->fragment_index;
  out_job->fragment_count = normal->fragment_count;
  out_job->timestamp = normal->timestamp;
  out_job->user_id = normal->user_id;
  out_job->action_id = normal->action_id;
  out_job->challenge = normal->challenge;
  memcpy(out_job->hmac, normal->hmac, sizeof(out_job->hmac));
  memcpy(out_job->ip, normal->ip, sizeof(out_job->ip));
  out_job->ip[sizeof(out_job->ip) - 1] = '\0';
  out_job->client_port = normal->client_port;
  out_job->encrypted = normal->encrypted;
  out_job->payload_len = normal->payload_len;
  if (normal->payload_len > 0u) {
    memcpy(out_job->payload_buffer, normal->payload_buffer, normal->payload_len);
  }
}

static void app_daemon3_copy_job_reply_to_mux(const AppConnectionJob *job,
                                              M7MuxNormalizedPacket *out_normal) {
  if (!job || !out_normal) {
    return;
  }

  memset(out_normal, 0, sizeof(*out_normal));
  out_normal->complete = job->complete;
  out_normal->should_reply = job->should_reply;
  out_normal->synthetic_session = job->synthetic_session;
  out_normal->wire_version = job->wire_version;
  out_normal->wire_form = job->wire_form;
  out_normal->received_ms = job->timestamp;
  out_normal->session_id = job->session_id;
  out_normal->message_id = job->message_id;
  out_normal->stream_id = job->stream_id;
  out_normal->fragment_index = job->fragment_index;
  out_normal->fragment_count = job->fragment_count;
  out_normal->timestamp = job->timestamp;
  out_normal->user_id = job->user_id;
  out_normal->action_id = SL_KNOCK_RESPONSE_ACTION_ID;
  out_normal->challenge = job->challenge;
  memcpy(out_normal->hmac, job->hmac, sizeof(out_normal->hmac));
  memcpy(out_normal->ip, job->ip, sizeof(out_normal->ip));
  out_normal->ip[sizeof(out_normal->ip) - 1] = '\0';
  out_normal->client_port = job->client_port;
  out_normal->encrypted = job->encrypted;
  out_normal->payload_len = job->response_len;
  if (job->response_len > 0u) {
    memcpy(out_normal->payload_buffer, job->response_buffer, job->response_len);
  }
  out_normal->response_len = 0u;
  memset(out_normal->response_buffer, 0, sizeof(out_normal->response_buffer));
}

static uint64_t app_daemon3_time_until_ms(uint64_t next_tick_at, uint64_t now_ms) {
  if (next_tick_at <= now_ms) {
    return 0;
  }

  return next_tick_at - now_ms;
}

static const AppDaemon3HelperLib app_daemon3_helper_instance = {
  .init = app_daemon3_helper_init,
  .shutdown = app_daemon3_helper_shutdown,
  .copy_job_to_knock_packet = app_daemon3_copy_job_to_knock_packet,
  .copy_mux_ingress_to_job = app_daemon3_copy_mux_ingress_to_job,
  .copy_job_reply_to_mux = app_daemon3_copy_job_reply_to_mux,
  .time_until_ms = app_daemon3_time_until_ms
};

const AppDaemon3HelperLib *get_app_daemon3_helper_lib(void) {
  return &app_daemon3_helper_instance;
}
