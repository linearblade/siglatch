/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_SAVE_CONFIG_H
#define SIGLATCH_SERVER_APP_BUILTIN_SAVE_CONFIG_H

#include "types.h"

int app_builtin_save_config_init(void);
void app_builtin_save_config_shutdown(void);
int app_builtin_save_config_handle(const AppBuiltinContext *ctx);

#endif
