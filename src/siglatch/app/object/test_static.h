/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_OBJECT_TEST_STATIC_H
#define SIGLATCH_SERVER_APP_OBJECT_TEST_STATIC_H

#include "types.h"

int app_object_test_static_init(void);
void app_object_test_static_shutdown(void);
int app_object_test_static_handle(const AppObjectContext *ctx, AppActionReply *reply);

#endif /* SIGLATCH_SERVER_APP_OBJECT_TEST_STATIC_H */
