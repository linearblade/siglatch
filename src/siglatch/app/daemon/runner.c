/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "runner.h"
#include "helper.h"
#include "job.h"
#include "tick.h"

#include <stdlib.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"
#include "../../../shared/knock/response.h"
#include "../../../shared/shared.h"
#include "../../../stdlib/protocol/udp/m7mux/internal.h"
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

static void app_daemon_configure_mux_policy(const AppRuntimeListenerState *listener,
                                            M7MuxState *mux_state) {
  if (!mux_state) {
    return;
  }

  if (listener && listener->server && listener->server->secure) {
    mux_state->policy_enforce_encryption = M7MUX_POLICY_ENFORCE_ENCRYPTION_YES;
    return;
  }

  mux_state->policy_enforce_encryption = M7MUX_POLICY_ENFORCE_ENCRYPTION_NO;
}

static int app_daemon_stage_raw_outbox_reply(M7MuxState *mux_state,
                                             AppRuntimeListenerState *listener,
                                             const AppConnectionJob *job) {
  M7MuxSendBytesPacket raw_send = {0};
  uint64_t now_ms = 0;
  size_t response_len = 0;

  if (!mux_state || !listener || !job) {
    return 0;
  }

  if (!job->response_buffer || job->response_len == 0u) {
    return 0;
  }

  response_len = job->response_len;
  if (response_len > M7MUX_NORMALIZED_PACKET_BUFFER_SIZE) {
    LOGW("[daemon.runner] Truncating raw reply from %zu to %u bytes\n",
         response_len,
         (unsigned)M7MUX_NORMALIZED_PACKET_BUFFER_SIZE);
    response_len = M7MUX_NORMALIZED_PACKET_BUFFER_SIZE;
  }

  raw_send.trace_id = 0u;
  memcpy(raw_send.label, "daemon", sizeof("daemon"));
  memcpy(raw_send.ip, job->ip, sizeof(raw_send.ip));
  raw_send.ip[sizeof(raw_send.ip) - 1u] = '\0';
  raw_send.client_port = job->client_port;
  raw_send.received_ms = job->timestamp;
  raw_send.bytes = job->response_buffer;
  raw_send.bytes_len = response_len;

  if (lib.m7mux.outbox.stage_bytes(mux_state, &raw_send)) {
    return 1;
  }

  now_ms = lib.time.monotonic_ms();
  if (lib.m7mux.outbox.flush(mux_state, listener->sock, now_ms) < 0) {
    return -1;
  }

  if (lib.m7mux.outbox.stage_bytes(mux_state, &raw_send)) {
    return 1;
  }

  LOGE("[daemon.runner] Failed to stage raw reply after flushing outbox\n");
  return 0;
}

static int app_daemon_stage_outbox_reply(M7MuxState *mux_state,
                                          AppRuntimeListenerState *listener,
                                          const AppConnectionJob *job) {
  if (!mux_state || !listener || !job) {
    return 0;
  }

  if (job->wire_version == 0u) {
    return app_daemon_stage_raw_outbox_reply(mux_state, listener, job);
  }

  M7MuxSendPacket send = {0};
  M7MuxUserSendData user = {0};
  uint64_t now_ms = 0;

  if (!app.daemon.helper.copy_job_reply_to_send(job, &send, &user)) {
    return 0;
  }

  if (lib.m7mux.outbox.stage(mux_state, &send)) {
    return 1;
  }

  now_ms = lib.time.monotonic_ms();
  if (lib.m7mux.outbox.flush(mux_state, listener->sock, now_ms) < 0) {
    return -1;
  }

  if (lib.m7mux.outbox.stage(mux_state, &send)) {
    return 1;
  }

  LOGE("[daemon.runner] Failed to stage reply after flushing outbox\n");
  return 0;
}

static int app_daemon_drain_jobs_and_flush(AppRuntimeListenerState *listener,
                                            M7MuxState *mux_state,
                                            AppJobState *job_state,
                                            SiglatchOpenSSLSession *session) {
  AppConnectionJob job = {0};
  uint64_t now_ms = 0;
  int rc = 0;

  while (app.daemon.job.drain(job_state, &job)) {
    (void)app.daemon.payload.consume(listener, &job, session);
    if (job.should_reply || job.response_len > 0u) {
      rc = app_daemon_stage_outbox_reply(mux_state, listener, &job);
      if (rc <= 0) {
        app.daemon.job.dispose(job_state, &job);
        return rc < 0 ? rc : -1;
      }
    }
    app.daemon.job.dispose(job_state, &job);
  }

  now_ms = lib.time.monotonic_ms();
  if (lib.m7mux.outbox.has_pending(mux_state)) {
    rc = lib.m7mux.outbox.flush(mux_state, listener->sock, now_ms);
    if (rc < 0) {
      return rc;
    }
  }

  return 0;
}

static int app_daemon_init(void) {
  return 1;
}

static void app_daemon_shutdown(void) {
}

static void app_daemon_run(AppRuntimeListenerState *listener) {
  SiglatchOpenSSLSession session = {0};
  AppWorkspace *workspace = NULL;
  M7MuxState *mux_state = NULL;
  AppJobState job_state = {0};
  M7MuxRecvPacket normal = {0};
  M7MuxUserRecvData user = {0};
  uint64_t now_ms = 0;
  uint64_t next_tick_at = 0;
  uint64_t timeout_ms = 0;
  int rc = 0;
  int tracked_sock = -1;
  int session_active = 0;
  int codec_session_installed = 0;

  if (!listener || !listener->process) {
    return;
  }

  if (!listener->server) {
    return;
  }

  if (!app.inbound.crypto.init_session_for_server(listener->server, &session)) {
    return;
  }
  session_active = 1;
  workspace = app.workspace.get();
  if (!workspace) {
    goto cleanup;
  }

  if (!workspace->codec_context) {
    goto cleanup;
  }

  if (!shared.knock.codec.context.set_openssl_session(workspace->codec_context, &session)) {
    goto cleanup;
  }
  codec_session_installed = 1;

  mux_state = lib.m7mux.connect.connect_socket(listener->sock);
  if (!mux_state) {
    goto cleanup;
  }
  app_daemon_configure_mux_policy(listener, mux_state);
  tracked_sock = listener->sock;

  if (!app.daemon.job.state_init(&job_state)) {
    goto cleanup;
  }

  (void)user;

  while (!app.signal.should_exit(listener->process)) {
    if (tracked_sock != listener->sock) {
      M7MuxState *next_mux_state = lib.m7mux.connect.connect_socket(listener->sock);

      if (!next_mux_state) {
        goto cleanup;
      }

      lib.m7mux.connect.disconnect(mux_state);
      mux_state = next_mux_state;
      app_daemon_configure_mux_policy(listener, mux_state);
      tracked_sock = listener->sock;
    }

    now_ms = lib.time.monotonic_ms();
    next_tick_at = app.daemon.tick.next_at(NULL, &job_state, now_ms);
    timeout_ms = app.daemon.helper.time_until_ms(next_tick_at, now_ms);

    rc = lib.m7mux.pump(mux_state, timeout_ms);
    if (rc < 0) {
      goto cleanup;
    }

    while (lib.m7mux.inbox.has_pending(mux_state)) {
      memset(&normal, 0, sizeof(normal));
      memset(&user, 0, sizeof(user));
      normal.user = &user;
      if (!lib.m7mux.inbox.drain(mux_state, &normal)) {
        break;
      }

      if (!app.daemon.job.enqueue(&job_state, &normal)) {
        continue;
      }
    }

    if (now_ms >= next_tick_at) {
      app.daemon.tick.run(NULL, &job_state, now_ms);
    }

    rc = app_daemon_drain_jobs_and_flush(listener, mux_state, &job_state, &session);
    if (rc < 0) {
      goto cleanup;
    }
  }

cleanup:
  if (codec_session_installed && workspace && workspace->codec_context) {
    shared.knock.codec.context.clear_openssl_session(workspace->codec_context);
    codec_session_installed = 0;
  }

  if (session_active) {
    app.runtime.invalidate_config_borrows(listener, &session);
  }
  app.daemon.job.state_reset(&job_state);
  if (mux_state) {
    lib.m7mux.connect.disconnect(mux_state);
  }
}

static const AppDaemonRunnerLib app_daemon_runner_instance = {
  .init = app_daemon_init,
  .shutdown = app_daemon_shutdown,
  .run = app_daemon_run
};

const AppDaemonRunnerLib *get_app_daemon_runner_lib(void) {
  return &app_daemon_runner_instance;
}
