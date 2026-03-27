/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "auth.h"

#include <string.h>

#include "../app.h"
#include "../../lib.h"

static int app_daemon3_auth_init(void) {
  return 1;
}

static void app_daemon3_auth_shutdown(void) {
}

static int app_daemon3_auth_authorize(SiglatchOpenSSLSession *session,
                                      AppConnectionJob *job) {
  const siglatch_user *user = NULL;
  KnockPacket pkt = {0};

  if (!job) {
    return 0;
  }

  job->authorized = 0;

  if (job->wire_version == 0u) {
    job->authorized = 1;
    return 1;
  }

  if (!session) {
    LOGE("[daemon3.auth] Null session for structured job (user_id=%u action_id=%u)\n",
         job->user_id,
         job->action_id);
    return 0;
  }

  user = app.config.user_by_id(job->user_id);
  if (!user) {
    LOGE("[daemon3.auth] No matching enabled user for user_id %u\n", job->user_id);
    return 0;
  }

  if (!app.inbound.crypto.assign_session_to_user(session, user)) {
    LOGE("[daemon3.auth] Failed to attach session to user_id %u\n", job->user_id);
    return 0;
  }

  if (!app.daemon3.helper.copy_job_to_knock_packet(job, &pkt)) {
    LOGE("[daemon3.auth] Failed to reconstruct auth packet from job (user_id=%u action_id=%u)\n",
         job->user_id,
         job->action_id);
    return 0;
  }

  if (!app.inbound.crypto.validate_signature(session, &pkt)) {
    return 0;
  }

  job->authorized = 1;
  return 1;
}

static const AppDaemon3AuthLib app_daemon3_auth_instance = {
  .init = app_daemon3_auth_init,
  .shutdown = app_daemon3_auth_shutdown,
  .authorize = app_daemon3_auth_authorize
};

const AppDaemon3AuthLib *get_app_daemon3_auth_lib(void) {
  return &app_daemon3_auth_instance;
}
