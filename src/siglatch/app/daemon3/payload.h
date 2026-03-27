/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_PAYLOAD_H
#define SIGLATCH_SERVER_APP_DAEMON3_PAYLOAD_H

#include "job.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*consume)(AppRuntimeListenerState *listener,
                 AppConnectionJob *job,
                 SiglatchOpenSSLSession *session);
} AppDaemon3PayloadLib;

const AppDaemon3PayloadLib *get_app_daemon3_payload_lib(void);

#endif
