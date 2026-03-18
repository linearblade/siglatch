/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_RUNTIME_H
#define SIGLATCH_SERVER_APP_RUNTIME_H

#include "../config/config.h"
#include "../../../stdlib/nonce.h"
#include "../../../stdlib/signal.h"

typedef struct SiglatchOpenSSLSession SiglatchOpenSSLSession;

typedef struct {
  SignalState signal;
} AppRuntimeProcessState;

typedef struct {
  int sock;
  int bound_port;
  char bound_ip[MAX_IP_RANGE_LEN];
  char config_path[PATH_MAX];
  const siglatch_server *server;
  unsigned long packet_count;
  NonceCache nonce;
  AppRuntimeProcessState *process;
} AppRuntimeListenerState;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*invalidate_config_borrows)(AppRuntimeListenerState *listener,
                                    SiglatchOpenSSLSession *session);
  int (*reload_config)(AppRuntimeListenerState *listener,
                       SiglatchOpenSSLSession *session,
                       const char *config_path,
                       const char *server_name);
} AppRuntimeLib;

const AppRuntimeLib *get_app_runtime_lib(void);

#endif
