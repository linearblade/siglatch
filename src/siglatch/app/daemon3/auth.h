/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_DAEMON3_AUTH_H
#define SIGLATCH_SERVER_APP_DAEMON3_AUTH_H

#include "job.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*authorize)(SiglatchOpenSSLSession *session, AppConnectionJob *job);
} AppDaemon3AuthLib;

const AppDaemon3AuthLib *get_app_daemon3_auth_lib(void);

#endif
