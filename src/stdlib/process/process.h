/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_PROCESS_H
#define SIGLATCH_PROCESS_H

#include "user/user.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  ProcessUserLib user;
} ProcessLib;

const ProcessLib *get_lib_process(void);

#endif /* SIGLATCH_PROCESS_H */
