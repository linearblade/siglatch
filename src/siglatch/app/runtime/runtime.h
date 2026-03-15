/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_RUNTIME_H
#define SIGLATCH_SERVER_APP_RUNTIME_H

#include "../config/config.h"
#include "../../../stdlib/nonce.h"
#include "../../../stdlib/signal.h"

typedef struct {
  SignalState signal;
} AppRuntimeProcessState;

typedef struct {
  int sock;
  const siglatch_server *server;
  unsigned long packet_count;
  NonceCache nonce;
  AppRuntimeProcessState *process;
} AppRuntimeListenerState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
} AppRuntimeLib;

const AppRuntimeLib *get_app_runtime_lib(void);

#endif
