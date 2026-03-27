/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_H
#define SIGLATCH_SERVER_APP_DAEMON3_H

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
  AppDaemon3HelperLib helper;
  AppDaemon3AuthLib auth;
  AppDaemon3RequestLib request;
  AppDaemon3PolicyLib policy;
  AppDaemon3RunnerLib runner;
  AppJobLib job;
  AppDaemon3PayloadLib payload;
  AppTickLib tick;
} AppDaemon3;

const AppDaemon3 *get_app_daemon3_lib(void);

#endif
