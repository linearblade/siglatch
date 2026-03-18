/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_REBIND_LISTENER_H
#define SIGLATCH_SERVER_APP_BUILTIN_REBIND_LISTENER_H

#include "types.h"

int app_builtin_rebind_listener_init(void);
void app_builtin_rebind_listener_shutdown(void);
int app_builtin_rebind_listener_handle(const AppBuiltinContext *ctx);

#endif
