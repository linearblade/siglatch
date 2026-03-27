/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_REQUEST_H
#define SIGLATCH_SERVER_APP_DAEMON3_REQUEST_H

#include "../config/config.h"
#include "job.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*resolve_user_action)(const AppConnectionJob *job,
                             const siglatch_user **out_user,
                             const siglatch_action **out_action);
  int (*bind_user_action)(const AppRuntimeListenerState *listener,
                          const AppConnectionJob *job,
                          SiglatchOpenSSLSession *session,
                          const siglatch_user **out_user,
                          const siglatch_action **out_action);
} AppDaemon3RequestLib;

const AppDaemon3RequestLib *get_app_daemon3_request_lib(void);

#endif
