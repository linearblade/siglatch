/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON4_PAYLOAD_H
#define SIGLATCH_SERVER_APP_DAEMON4_PAYLOAD_H

#include "job.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*consume)(AppRuntimeListenerState *listener,
                 AppConnectionJob *job,
                 SiglatchOpenSSLSession *session);
} AppDaemon4PayloadLib;

const AppDaemon4PayloadLib *get_app_daemon4_payload_lib(void);

#endif
