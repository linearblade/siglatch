/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_CHANGE_SETTING_H
#define SIGLATCH_SERVER_APP_BUILTIN_CHANGE_SETTING_H

#include "types.h"

int app_builtin_change_setting_init(void);
void app_builtin_change_setting_shutdown(void);
int app_builtin_change_setting_handle(const AppBuiltinContext *ctx);

#endif
