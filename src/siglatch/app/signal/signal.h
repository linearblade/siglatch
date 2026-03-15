/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#ifndef SIGLATCH_SERVER_APP_SIGNAL_H
#define SIGLATCH_SERVER_APP_SIGNAL_H

#include "../runtime/runtime.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*install)(AppRuntimeProcessState *process);
  int (*should_exit)(const AppRuntimeProcessState *process);
  void (*request_exit)(AppRuntimeProcessState *process);
} AppSignalLib;

const AppSignalLib *get_app_signal_lib(void);

#endif
