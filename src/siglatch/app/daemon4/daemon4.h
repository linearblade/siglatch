/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_H
#define SIGLATCH_SERVER_APP_DAEMON4_H

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
  AppDaemon4HelperLib helper;
  AppDaemon4AuthLib auth;
  AppDaemon4RequestLib request;
  AppDaemon4PolicyLib policy;
  AppDaemon4RunnerLib runner;
  AppJobLib job;
  AppDaemon4PayloadLib payload;
  AppTickLib tick;
} AppDaemon4;

const AppDaemon4 *get_app_daemon4_lib(void);

#endif
