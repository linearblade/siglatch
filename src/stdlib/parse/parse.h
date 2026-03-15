/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PARSE_H
#define SIGLATCH_STDLIB_PARSE_H

#include "ini.h"

typedef struct {
  const StrLib *str;
} ParseContext;

typedef struct {
  int (*init)(const ParseContext *ctx);
  void (*shutdown)(void);
  int (*set_context)(const ParseContext *ctx);
  IniLib ini;
} ParseLib;

const ParseLib *get_lib_parse(void);

#endif
