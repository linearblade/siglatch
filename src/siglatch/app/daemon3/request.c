/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "request.h"

#include <string.h>

#include "../app.h"
#include "../../lib.h"

static int app_daemon3_request_init(void) {
  return 1;
}

static void app_daemon3_request_shutdown(void) {
}

static int app_daemon3_request_resolve_user_action(const AppConnectionJob *job,
                                                   const siglatch_user **out_user,
                                                   const siglatch_action **out_action) {
  if (!job || !out_user || !out_action) {
    return 0;
  }

  *out_user = app.config.user_by_id(job->user_id);
  *out_action = app.config.action_by_id(job->action_id);
  return *out_user && *out_action;
}

static int app_daemon3_request_bind_user_action(const AppRuntimeListenerState *listener,
                                                const AppConnectionJob *job,
                                                SiglatchOpenSSLSession *session,
                                                const siglatch_user **out_user,
                                                const siglatch_action **out_action) {
  const siglatch_user *user = NULL;
  const siglatch_action *action = NULL;

  if (!listener || !listener->server || !job || !session || !out_user || !out_action) {
    return 0;
  }

  user = app.config.user_by_id(job->user_id);
  if (!user) {
    LOGW("[daemon3.request] No matching enabled user for user_id %u\n", job->user_id);
    return 0;
  }

  if (!app.inbound.crypto.assign_session_to_user(session, user)) {
    LOGE("[daemon3.request] Failed to assign session to user ID: %u\n", job->user_id);
    return 0;
  }

  action = app.config.action_by_id(job->action_id);
  if (!action) {
    LOGW("[daemon3.request] Unknown action ID: %u\n", job->action_id);
    return 0;
  }

  *out_user = user;
  *out_action = action;
  return 1;
}

static const AppDaemon3RequestLib app_daemon3_request_instance = {
  .init = app_daemon3_request_init,
  .shutdown = app_daemon3_request_shutdown,
  .resolve_user_action = app_daemon3_request_resolve_user_action,
  .bind_user_action = app_daemon3_request_bind_user_action
};

const AppDaemon3RequestLib *get_app_daemon3_request_lib(void) {
  return &app_daemon3_request_instance;
}
