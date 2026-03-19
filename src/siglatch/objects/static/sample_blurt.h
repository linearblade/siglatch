/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_OBJECTS_STATIC_SAMPLE_BLURT_H
#define SIGLATCH_OBJECTS_STATIC_SAMPLE_BLURT_H

#include "../../app/object/types.h"

int siglatch_object_sample_blurt_static_init(void);
void siglatch_object_sample_blurt_static_shutdown(void);
int siglatch_object_sample_blurt_static_handle(const AppObjectContext *ctx, AppActionReply *reply);

#endif /* SIGLATCH_OBJECTS_STATIC_SAMPLE_BLURT_H */
