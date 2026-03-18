/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_BUILTIN_TEST_BLURT_H
#define SIGLATCH_SERVER_APP_BUILTIN_TEST_BLURT_H

#include "types.h"

int app_builtin_test_blurt_init(void);
void app_builtin_test_blurt_shutdown(void);
int app_builtin_test_blurt_handle(const AppBuiltinContext *ctx);

#endif
