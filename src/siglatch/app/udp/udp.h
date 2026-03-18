/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_UDP_H
#define SIGLATCH_SERVER_APP_UDP_H

#include "../runtime/runtime.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*start_listener)(AppRuntimeListenerState *listener);
  int (*probe_bind)(const AppRuntimeListenerState *listener,
                    const siglatch_server *server);
  int (*rebind_listener)(AppRuntimeListenerState *listener,
                         const siglatch_server *server);
} AppUdpLib;

const AppUdpLib *get_app_udp_lib(void);

#endif
