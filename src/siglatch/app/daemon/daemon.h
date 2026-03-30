/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_H
#define SIGLATCH_SERVER_APP_DAEMON_H

#include "helper.h"
#include "auth.h"
#include "job.h"
#include "request.h"
#include "policy.h"
#include "payload.h"
#include "runner.h"
#include "tick.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*process)(AppRuntimeListenerState *listener);
  AppDaemonHelperLib helper;
  AppDaemonAuthLib auth;
  AppDaemonRequestLib request;
  AppDaemonPolicyLib policy;
  AppDaemonRunnerLib runner;
  AppJobLib job;
  AppDaemonPayloadLib payload;
  AppTickLib tick;
} AppDaemon;

const AppDaemon *get_app_daemon_lib(void);

#endif
