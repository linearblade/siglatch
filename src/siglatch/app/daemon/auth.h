/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON_AUTH_H
#define SIGLATCH_SERVER_APP_DAEMON_AUTH_H

#include "job.h"
#include "../../../stdlib/openssl/session/session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*authorize)(SiglatchOpenSSLSession *session, AppConnectionJob *job);
} AppDaemonAuthLib;

const AppDaemonAuthLib *get_app_daemon_auth_lib(void);

#endif
