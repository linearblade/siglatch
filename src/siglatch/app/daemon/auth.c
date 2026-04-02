/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "auth.h"

#include <string.h>

#include "../app.h"
#include "../../lib.h"

static int app_daemon_auth_init(void) {
  return 1;
}

static void app_daemon_auth_shutdown(void) {
}

static int app_daemon_auth_authorize(SiglatchOpenSSLSession *session,
                                      AppConnectionJob *job) {
  const siglatch_user *user = NULL;

  if (!job) {
    return 0;
  }

  job->wire_auth = 0;

  if (job->wire_version == 0u) {
    job->wire_auth = 1;
    return 1;
  }

  if (!session) {
    LOGE("[daemon.auth] Null session for structured job (user_id=%u action_id=%u)\n",
         job->request.user_id,
         job->request.action_id);
    return 0;
  }

  user = app.config.user_by_id(job->request.user_id);
  if (!user) {
    LOGE("[daemon.auth] No matching enabled user for user_id %u\n", job->request.user_id);
    return 0;
  }

  if (!app.inbound.crypto.assign_session_to_user(session, user)) {
    LOGE("[daemon.auth] Failed to attach session to user_id %u\n", job->request.user_id);
    return 0;
  }

  if (!app.inbound.crypto.validate_signature(session, job)) {
    return 0;
  }

  job->wire_auth = 1;
  return 1;
}

static const AppDaemonAuthLib app_daemon_auth_instance = {
  .init = app_daemon_auth_init,
  .shutdown = app_daemon_auth_shutdown,
  .authorize = app_daemon_auth_authorize
};

const AppDaemonAuthLib *get_app_daemon_auth_lib(void) {
  return &app_daemon_auth_instance;
}
