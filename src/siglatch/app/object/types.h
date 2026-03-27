/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_OBJECT_TYPES_H
#define SIGLATCH_SERVER_APP_OBJECT_TYPES_H

#include "../config/config.h"
#include "../daemon3/job.h"
#include "../payload/reply.h"
#include "../runtime/runtime.h"
#include "../../../stdlib/openssl_session.h"

typedef struct {
  AppRuntimeListenerState *listener;
  const AppConnectionJob *job;
  SiglatchOpenSSLSession *session;
  const siglatch_user *user;
  const siglatch_action *action;
  const char *ip_addr;
} AppObjectContext;

typedef int (*AppObjectHandlerFn)(const AppObjectContext *ctx, AppActionReply *reply);

#endif /* SIGLATCH_SERVER_APP_OBJECT_TYPES_H */
