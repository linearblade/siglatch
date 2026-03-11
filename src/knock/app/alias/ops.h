/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ALIAS_OPS_H
#define SIGLATCH_KNOCK_APP_ALIAS_OPS_H

#include <stdint.h>

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*set_user)(const char *host, const char *user, uint32_t user_id);
  int (*set_action)(const char *host, const char *action, uint32_t action_id);
  int (*show_user)(const char *host);
  int (*show_user_all)(void);
  int (*delete_user)(const char *host, const char *user);
  int (*delete_user_map)(const char *host);
  int (*show_action)(const char *host);
  int (*show_action_all)(void);
  int (*delete_action)(const char *host, const char *action);
  int (*delete_action_map)(const char *host);
  int (*show_host)(const char *host);
  int (*show_hosts)(void);
  int (*delete_host)(const char *host);
} AppAliasOpsLib;

const AppAliasOpsLib *get_app_alias_ops_lib(void);

#endif
