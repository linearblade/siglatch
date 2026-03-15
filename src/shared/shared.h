/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_H
#define SIGLATCH_SHARED_H

#include "../stdlib/log.h"
#include "../stdlib/openssl.h"
#include "../stdlib/print.h"
#include "knock/codec.h"
#include "knock/debug.h"
#include "knock/digest.h"

typedef struct {
  const Logger *log;
  const SiglatchOpenSSL_Lib *openssl;
  const PrintLib *print;
} SharedContext;

typedef struct {
  SharedKnockCodecLib codec;
  SharedKnockDebugLib debug;
  SharedKnockDigestLib digest;
} SharedKnockLib;

typedef struct {
  SharedKnockLib knock;
} Shared;

extern Shared shared;

int init_shared(const SharedContext *ctx);
void shutdown_shared(void);

#endif
