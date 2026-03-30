/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_PAYLOAD_H
#define SIGLATCH_SERVER_APP_DAEMON_PAYLOAD_H

#include "job.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*consume)(AppRuntimeListenerState *listener,
                 AppConnectionJob *job,
                 SiglatchOpenSSLSession *session);
} AppDaemonPayloadLib;

const AppDaemonPayloadLib *get_app_daemon_payload_lib(void);

#endif
