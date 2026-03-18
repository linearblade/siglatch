/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_POLICY_H
#define SIGLATCH_SERVER_APP_POLICY_H

#include "../config/config.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*server_ip_allowed)(const siglatch_server *server, const char *ip_addr);
  int (*user_ip_allowed)(const siglatch_user *user, const char *ip_addr);
  int (*action_ip_allowed)(const siglatch_action *action, const char *ip_addr);
  int (*request_ip_allowed)(const siglatch_server *server,
                            const siglatch_user *user,
                            const siglatch_action *action,
                            const char *ip_addr);
} AppPolicyLib;

const AppPolicyLib *get_app_policy_lib(void);

#endif
