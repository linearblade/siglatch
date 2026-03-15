/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_H
#define SIGLATCH_SERVER_APP_DAEMON_H

#include "../runtime/runtime.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*run)(AppRuntimeListenerState *listener);
} AppDaemonLib;

const AppDaemonLib *get_app_daemon_lib(void);

#endif
