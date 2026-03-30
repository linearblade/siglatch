/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_H
#define SIGLATCH_SERVER_APP_BUILTIN_H

#include "change_setting.h"
#include "list_users.h"
#include "load_config.h"
#include "probe_rebind.h"
#include "rebind_listener.h"
#include "reload_config.h"
#include "save_config.h"
#include "version.h"
#include "test_blurt.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*supports)(const char *name);
  int (*is_action)(const siglatch_action *action);
  int (*build_context)(
      AppBuiltinContext *out,
      AppRuntimeListenerState *listener,
      const AppConnectionJob *job,
      SiglatchOpenSSLSession *session,
      const siglatch_user *user,
      const siglatch_action *action,
      const char *ip_addr);
  int (*handle)(const AppBuiltinContext *ctx, AppActionReply *reply);
  AppBuiltinHandlerLib probe_rebind;
  AppBuiltinHandlerLib rebind_listener;
  AppBuiltinHandlerLib reload_config;
  AppBuiltinHandlerLib change_setting;
  AppBuiltinHandlerLib save_config;
  AppBuiltinHandlerLib load_config;
  AppBuiltinHandlerLib list_users;
  AppBuiltinHandlerLib version;
  AppBuiltinHandlerLib test_blurt;
} AppBuiltinLib;

const AppBuiltinLib *get_app_builtin_lib(void);

#endif
