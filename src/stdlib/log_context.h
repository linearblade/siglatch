/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_LOG_CONTEXT_H
#define SIGLATCH_LOG_CONTEXT_H
#include "time.h"
#include "print.h"

typedef struct {
  const TimeLib *time;
  const PrintLib *print;
} LogContext;

#endif // SIGLATCH_LOG_CONTEXT_H
