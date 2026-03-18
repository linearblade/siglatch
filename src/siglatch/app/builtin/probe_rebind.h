/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_PROBE_REBIND_H
#define SIGLATCH_SERVER_APP_BUILTIN_PROBE_REBIND_H

#include "types.h"

int app_builtin_probe_rebind_init(void);
void app_builtin_probe_rebind_shutdown(void);
int app_builtin_probe_rebind_handle(const AppBuiltinContext *ctx);

#endif
