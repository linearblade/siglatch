/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "policy.h"

#include "../../lib.h"
#include "../app.h"

static int app_daemon3_policy_init(void) {
  return 1;
}

static void app_daemon3_policy_shutdown(void) {
}

static int app_daemon3_policy_enforce(const AppRuntimeListenerState *listener,
                                      const AppConnectionJob *job,
                                      const siglatch_user *user,
                                      const siglatch_action *action) {
  if (!listener || !listener->server || !job || !user || !action) {
    return 0;
  }

  if (!app.server.action_available(listener->server, action->name)) {
    LOGE("[daemon3.policy] Action (%s) not permitted on this server.\n", action->name);
    return 0;
  }

  if (!app.config.action_available_by_user(job->user_id, action->name)) {
    LOGE("[daemon3.policy] Action (%s) not permitted by this user(%s).\n",
         action->name,
         user->name);
    return 0;
  }

  if (!action->enabled) {
    LOGE("[daemon3.policy] Action is disabled.\n");
    return 0;
  }

  if (!app.policy.request_ip_allowed(listener->server, user, action, job->ip)) {
    if (!app.policy.server_ip_allowed(listener->server, job->ip)) {
      LOGE("[daemon3.policy] Source IP (%s) is not permitted on this server(%s).\n",
           job->ip,
           listener->server->name);
      return 0;
    }

    if (!app.policy.user_ip_allowed(user, job->ip)) {
      LOGE("[daemon3.policy] Source IP (%s) is not permitted for user(%s).\n",
           job->ip,
           user->name);
      return 0;
    }

    if (!app.policy.action_ip_allowed(action, job->ip)) {
      LOGE("[daemon3.policy] Source IP (%s) is not permitted for action(%s).\n",
           job->ip,
           action->name);
      return 0;
    }

    LOGE("[daemon3.policy] Source IP (%s) is not permitted by request policy.\n", job->ip);
    return 0;
  }

  return 1;
}

static const AppDaemon3PolicyLib app_daemon3_policy_instance = {
  .init = app_daemon3_policy_init,
  .shutdown = app_daemon3_policy_shutdown,
  .enforce = app_daemon3_policy_enforce
};

const AppDaemon3PolicyLib *get_app_daemon3_policy_lib(void) {
  return &app_daemon3_policy_instance;
}
