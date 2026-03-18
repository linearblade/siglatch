/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_LIST_USERS_H
#define SIGLATCH_SERVER_APP_BUILTIN_LIST_USERS_H

#include "types.h"

int app_builtin_list_users_init(void);
void app_builtin_list_users_shutdown(void);
int app_builtin_list_users_handle(const AppBuiltinContext *ctx);

#endif
