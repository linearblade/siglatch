/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_STARTUP_H
#define SIGLATCH_SERVER_APP_STARTUP_H

#include "../opts/opts.h"
#include "../runtime/runtime.h"

typedef struct {
  int should_exit;
  int exit_code;
  AppParsedOpts parsed;
  const siglatch_config *cfg;
  AppRuntimeProcessState process;
  AppRuntimeListenerState listener;
} AppStartupState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*prepare)(int argc, char *argv[], AppStartupState *state);
} AppStartupLib;

const AppStartupLib *get_app_startup_lib(void);

#endif
