/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_PARSE_INI_H
#define SIGLATCH_STDLIB_PARSE_INI_H

#include <stddef.h>
#include "../str.h"

typedef struct {
  char *key;
  char *value;
  size_t line;
} IniEntry;

typedef struct {
  char *name;
  size_t line;
  IniEntry *entries;
  size_t entry_count;
} IniSection;

typedef struct {
  IniSection global;
  IniSection *sections;
  size_t section_count;
} IniDocument;

typedef struct {
  size_t line;
  char message[256];
} IniError;

typedef struct {
  const StrLib *str;
} IniContext;

typedef struct {
  int (*init)(const IniContext *ctx);
  void (*shutdown)(void);
  int (*set_context)(const IniContext *ctx);
  IniDocument *(*read_file)(const char *path, IniError *error);
  void (*destroy)(IniDocument *document);
  const IniSection *(*find_section)(const IniDocument *document, const char *name);
  const IniEntry *(*find_entry)(const IniSection *section, const char *key);
  const char *(*get)(const IniDocument *document, const char *section, const char *key);
} IniLib;

const IniLib *get_lib_parse_ini(void);

#endif
