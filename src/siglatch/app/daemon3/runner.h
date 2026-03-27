/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_RUNNER_H
#define SIGLATCH_SERVER_APP_DAEMON3_RUNNER_H

#include "../runtime/runtime.h"

/*
 * Shape-only scaffolding for the next daemon loop.
 *
 * This file is intentionally not wired into the live runtime yet.
 * The goal is to capture the new listener -> connection -> job loop
 * in code form so it can be refined line by line.
 */

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*run)(AppRuntimeListenerState *listener);
} AppDaemon3RunnerLib;

const AppDaemon3RunnerLib *get_app_daemon3_runner_lib(void);

#endif
