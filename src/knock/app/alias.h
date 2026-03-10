/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ALIAS_H
#define SIGLATCH_KNOCK_APP_ALIAS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  char name[128];
  char host[256];
  uint32_t id;
} AliasEntry;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*read_map)(const char *path, AliasEntry **out_list, size_t *out_count);
  int (*update_entry)(AliasEntry **list, size_t *count, const char *name, const char *host, uint32_t id);
  int (*write_map)(const char *path, AliasEntry *list, size_t count);
  uint32_t (*resolve_user)(const char *host, const char *name);
  uint32_t (*resolve_action)(const char *host, const char *name);
} AppAliasLib;

const AppAliasLib *get_app_alias_lib(void);

#endif
