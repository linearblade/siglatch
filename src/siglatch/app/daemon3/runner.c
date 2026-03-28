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
#include "../../../stdlib/protocol/udp/m7mux/normalize/normalize.h"

static int app_daemon3_stage_outbox_reply(M7MuxState *mux_state,
                                          AppRuntimeListenerState *listener,
                                          const M7MuxNormalizedPacket *normal) {
  M7MuxNormalizedPacket serialized = {0};
  uint64_t now_ms = 0;

  if (!mux_state || !listener || !normal) {
    return 0;
  }

  serialized = *normal;

  if (lib.m7mux.outbox.stage(mux_state, &serialized)) {
    return 1;
  }

  now_ms = lib.time.monotonic_ms();
  if (lib.m7mux.outbox.flush(mux_state, listener->sock, now_ms) < 0) {
    return -1;
  }

  if (lib.m7mux.outbox.stage(mux_state, &serialized)) {
    return 1;
  }

  LOGE("[daemon3.runner] Failed to stage reply after flushing outbox\n");
  return 0;
}

static int app_daemon3_drain_jobs_and_flush(AppRuntimeListenerState *listener,
                                            M7MuxState *mux_state,
                                            AppJobState *job_state,
                                            SiglatchOpenSSLSession *session) {
  AppConnectionJob job = {0};
  M7MuxNormalizedPacket normal = {0};
  uint64_t now_ms = 0;
  int rc = 0;

  while (app.daemon3.job.drain(job_state, &job)) {
    (void)app.daemon3.payload.consume(listener, &job, session);
    if (job.should_reply || job.response_len > 0u) {
      memset(&normal, 0, sizeof(normal));
      if (!app.daemon3.helper.copy_job_reply_to_mux(&job, &normal)) {
        app.daemon3.job.dispose(job_state, &job);
        return -1;
      }
      rc = app_daemon3_stage_outbox_reply(mux_state, listener, &normal);
      if (rc <= 0) {
        app.daemon3.job.dispose(job_state, &job);
        return rc < 0 ? rc : -1;
      }
    }
    app.daemon3.job.dispose(job_state, &job);
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

static int app_daemon3_init(void) {
  return 1;
}

static void app_daemon3_shutdown(void) {
}

static void app_daemon3_run(AppRuntimeListenerState *listener) {
  SiglatchOpenSSLSession session = {0};
  AppWorkspace *workspace = NULL;
  M7MuxState *mux_state = NULL;
  AppJobState job_state = {0};
  M7MuxNormalizedPacket normal = {0};
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

  if (!shared.knock.codec2.context.set_openssl_session(workspace->codec_context, &session)) {
    goto cleanup;
  }
  codec_session_installed = 1;

  mux_state = lib.m7mux.connect.connect_socket(listener->sock);
  if (!mux_state) {
    goto cleanup;
  }
  tracked_sock = listener->sock;

  if (!app.daemon3.job.state_init(&job_state)) {
    goto cleanup;
  }

  while (!app.signal.should_exit(listener->process)) {
    if (tracked_sock != listener->sock) {
      M7MuxState *next_mux_state = lib.m7mux.connect.connect_socket(listener->sock);

      if (!next_mux_state) {
        goto cleanup;
      }

      lib.m7mux.connect.disconnect(mux_state);
      mux_state = next_mux_state;
      tracked_sock = listener->sock;
    }

    now_ms = lib.time.monotonic_ms();
    next_tick_at = app.daemon3.tick.next_at(NULL, &job_state, now_ms);
    timeout_ms = app.daemon3.helper.time_until_ms(next_tick_at, now_ms);

    rc = lib.m7mux.pump(mux_state, timeout_ms);
    if (rc < 0) {
      goto cleanup;
    }

    while (lib.m7mux.inbox.has_pending(mux_state)) {
      memset(&normal, 0, sizeof(normal));
      if (!lib.m7mux.inbox.drain(mux_state, &normal)) {
        break;
      }

      if (!app.daemon3.job.enqueue(&job_state, &normal)) {
        continue;
      }
    }

    if (now_ms >= next_tick_at) {
      app.daemon3.tick.run(NULL, &job_state, now_ms);
    }

    rc = app_daemon3_drain_jobs_and_flush(listener, mux_state, &job_state, &session);
    if (rc < 0) {
      goto cleanup;
    }
  }

cleanup:
  if (codec_session_installed && workspace && workspace->codec_context) {
    shared.knock.codec2.context.clear_openssl_session(workspace->codec_context);
    codec_session_installed = 0;
  }

  if (session_active) {
    app.runtime.invalidate_config_borrows(listener, &session);
  }
  app.daemon3.job.state_reset(&job_state);
  if (mux_state) {
    lib.m7mux.connect.disconnect(mux_state);
  }
}

static const AppDaemon3RunnerLib app_daemon3_runner_instance = {
  .init = app_daemon3_init,
  .shutdown = app_daemon3_shutdown,
  .run = app_daemon3_run
};

const AppDaemon3RunnerLib *get_app_daemon3_runner_lib(void) {
  return &app_daemon3_runner_instance;
}
