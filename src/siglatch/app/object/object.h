/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_OBJECT_H
#define SIGLATCH_SERVER_APP_OBJECT_H

#include "test_static.h"
#include "../../objects/static/sample_blurt.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*supports_static)(const char *name);
  int (*supports_dynamic)(const char *path, const char *name);
  int (*build_context)(
      AppObjectContext *out,
      AppRuntimeListenerState *listener,
      const AppConnectionJob *job,
      SiglatchOpenSSLSession *session,
      const siglatch_user *user,
      const siglatch_action *action,
      const char *ip_addr);
  int (*run_static)(const AppObjectContext *ctx, AppActionReply *reply);
  int (*run_dynamic)(const AppObjectContext *ctx, AppActionReply *reply);
} AppObjectLib;

const AppObjectLib *get_app_object_lib(void);

#endif /* SIGLATCH_SERVER_APP_OBJECT_H */
