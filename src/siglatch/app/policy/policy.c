/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "policy.h"

#include "../../lib.h"

static int app_policy_init(void) {
  return 1;
}

static void app_policy_shutdown(void) {
}

static int app_policy_server_ip_allowed(const siglatch_server *server,
                                        const char *ip_addr) {
  int i = 0;

  if (!server || !ip_addr || ip_addr[0] == '\0') {
    return 0;
  }

  if (server->allowed_ip_count <= 0) {
    return 1;
  }

  for (i = 0; i < server->allowed_ip_count; ++i) {
    if (lib.net.ip.range.contains_spec_ipv4(server->allowed_ips[i], ip_addr)) {
      return 1;
    }
  }

  return 0;
}

static int app_policy_user_ip_allowed(const siglatch_user *user,
                                      const char *ip_addr) {
  int i = 0;

  if (!user || !ip_addr || ip_addr[0] == '\0') {
    return 0;
  }

  if (user->allowed_ip_count <= 0) {
    return 1;
  }

  for (i = 0; i < user->allowed_ip_count; ++i) {
    if (lib.net.ip.range.contains_spec_ipv4(user->allowed_ips[i], ip_addr)) {
      return 1;
    }
  }

  return 0;
}

static int app_policy_action_ip_allowed(const siglatch_action *action,
                                        const char *ip_addr) {
  int i = 0;

  if (!action || !ip_addr || ip_addr[0] == '\0') {
    return 0;
  }

  if (action->allowed_ip_count <= 0) {
    return 1;
  }

  for (i = 0; i < action->allowed_ip_count; ++i) {
    if (lib.net.ip.range.contains_spec_ipv4(action->allowed_ips[i], ip_addr)) {
      return 1;
    }
  }

  return 0;
}

static int app_policy_request_ip_allowed(const siglatch_server *server,
                                         const siglatch_user *user,
                                         const siglatch_action *action,
                                         const char *ip_addr) {
  if (!server || !user || !action || !ip_addr || ip_addr[0] == '\0') {
    return 0;
  }

  if (!app_policy_server_ip_allowed(server, ip_addr)) {
    return 0;
  }

  if (!app_policy_user_ip_allowed(user, ip_addr)) {
    return 0;
  }

  if (!app_policy_action_ip_allowed(action, ip_addr)) {
    return 0;
  }

  return 1;
}

static const AppPolicyLib app_policy_instance = {
  .init = app_policy_init,
  .shutdown = app_policy_shutdown,
  .server_ip_allowed = app_policy_server_ip_allowed,
  .user_ip_allowed = app_policy_user_ip_allowed,
  .action_ip_allowed = app_policy_action_ip_allowed,
  .request_ip_allowed = app_policy_request_ip_allowed
};

const AppPolicyLib *get_app_policy_lib(void) {
  return &app_policy_instance;
}
