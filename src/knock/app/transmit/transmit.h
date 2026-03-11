/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_TRANSMIT_H
#define SIGLATCH_KNOCK_APP_TRANSMIT_H

#include "../opts/contract.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*singlePacket)(const Opts *opts);
} AppTransmitLib;

const AppTransmitLib *get_app_transmit_lib(void);

#endif
