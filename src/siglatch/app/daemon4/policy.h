/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_POLICY_H
#define SIGLATCH_SERVER_APP_DAEMON4_POLICY_H

#include "../config/config.h"
#include "job.h"
#include "../runtime/runtime.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*enforce)(const AppRuntimeListenerState *listener,
                 const AppConnectionJob *job,
                 const siglatch_user *user,
                 const siglatch_action *action);
} AppDaemon4PolicyLib;

const AppDaemon4PolicyLib *get_app_daemon4_policy_lib(void);

#endif
