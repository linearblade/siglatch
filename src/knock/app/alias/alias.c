/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "alias.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"
#include "command.h"

static AppAliasCommandLib app_alias_command = {0};

static int app_alias_init(void) {
  app_alias_command = *get_app_alias_command_lib();
  return app_alias_command.init();
}

static void app_alias_shutdown(void) {
  app_alias_command.shutdown();
}

static int app_alias_read_map(const char *path, AliasEntry **out_list, size_t *out_count) {
  FILE *fp = NULL;
  AliasEntry *list = NULL;
  size_t count = 0;
  size_t capacity = 0;
  char line[512];

  if (!path || !out_list || !out_count) {
    return 0;
  }

  fp = fopen(path, "r");
  if (!fp) {
    lib.print.uc_fprintf(stderr, "err", "Failed to open alias file for reading: %s (%s)\n", path, strerror(errno));
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *name = strtok(line, ",");
    char *host = strtok(NULL, ",");
    char *id_str = strtok(NULL, ",\n");

    if (!name || !host || !id_str) {
      lib.print.uc_fprintf(stderr, "warn", "Skipping invalid alias line: %s\n", line);
      continue;
    }

    if (count >= capacity) {
      size_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
      AliasEntry *new_list = realloc(list, new_capacity * sizeof(AliasEntry));
      if (!new_list) {
        lib.print.uc_fprintf(stderr, "err", "Memory allocation failed while reading alias file.\n");
        free(list);
        fclose(fp);
        return 0;
      }
      list = new_list;
      capacity = new_capacity;
    }

    strncpy(list[count].name, name, sizeof(list[count].name) - 1);
    list[count].name[sizeof(list[count].name) - 1] = '\0';
    strncpy(list[count].host, host, sizeof(list[count].host) - 1);
    list[count].host[sizeof(list[count].host) - 1] = '\0';
    list[count].id = (uint32_t)atoi(id_str);
    count++;
  }

  fclose(fp);

  *out_list = list;
  *out_count = count;
  return 1;
}

static int app_alias_update_entry(AliasEntry **list, size_t *count, const char *name, const char *host, uint32_t id) {
  if (!list || !count || !name || !host) {
    return 0;
  }

  for (size_t i = 0; i < *count; i++) {
    if (strcmp((*list)[i].name, name) == 0) {
      (*list)[i].id = id;
      strncpy((*list)[i].host, host, sizeof((*list)[i].host) - 1);
      (*list)[i].host[sizeof((*list)[i].host) - 1] = '\0';
      lib.print.uc_printf("update", "Updated alias: %s -> %s (id=%u)\n", name, host, id);
      return 1;
    }
  }

  {
    AliasEntry *new_list = realloc(*list, (*count + 1) * sizeof(AliasEntry));
    AliasEntry *new_entry = NULL;

    if (!new_list) {
      lib.print.uc_fprintf(stderr, "err", "Memory allocation failed in update_alias_entry()\n");
      return 0;
    }

    *list = new_list;
    new_entry = &(*list)[*count];
    strncpy(new_entry->name, name, sizeof(new_entry->name) - 1);
    new_entry->name[sizeof(new_entry->name) - 1] = '\0';
    strncpy(new_entry->host, host, sizeof(new_entry->host) - 1);
    new_entry->host[sizeof(new_entry->host) - 1] = '\0';
    new_entry->id = id;
    (*count)++;
  }

  lib.print.uc_printf("target", "Created new alias: %s -> %s (id=%u)\n", name, host, id);
  return 1;
}

static int app_alias_write_map(const char *path, AliasEntry *list, size_t count) {
  FILE *fp = NULL;

  if (!path || (count > 0 && !list)) {
    return 0;
  }

  fp = fopen(path, "w");
  if (!fp) {
    lib.print.uc_fprintf(stderr, "err", "Failed to open alias map for writing: %s (%s)\n", path, strerror(errno));
    return 0;
  }

  for (size_t i = 0; i < count; i++) {
    fprintf(fp, "%s,%s,%u\n", list[i].name, list[i].host, list[i].id);
  }

  fclose(fp);
  lib.print.uc_printf("ok", "Alias map written successfully: %s (%zu entries)\n", path, count);
  return 1;
}

static uint32_t app_alias_resolve_action(const char *host, const char *name) {
  char path[PATH_MAX];
  AliasEntry *list = NULL;
  size_t count = 0;
  uint32_t id = 0;

  if (!host || !name) {
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "action.map")) {
    return 0;
  }

  if (!app_alias_read_map(path, &list, &count)) {
    return 0;
  }

  for (size_t i = 0; i < count; i++) {
    if (strcmp(list[i].name, name) == 0) {
      id = list[i].id;
      break;
    }
  }

  free(list);
  return id;
}

static uint32_t app_alias_resolve_user(const char *host, const char *name) {
  char path[PATH_MAX];
  AliasEntry *list = NULL;
  size_t count = 0;
  uint32_t id = 0;

  if (!host || !name) {
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "user.map")) {
    return 0;
  }

  if (!app_alias_read_map(path, &list, &count)) {
    return 0;
  }

  for (size_t i = 0; i < count; i++) {
    if (strcmp(list[i].name, name) == 0) {
      id = list[i].id;
      break;
    }
  }

  free(list);
  return id;
}

static int app_alias_execute(const AppAliasCommand *cmd) {
  return app_alias_command.execute(cmd);
}

static const AppAliasLib app_alias_instance = {
  .init = app_alias_init,
  .shutdown = app_alias_shutdown,
  .read_map = app_alias_read_map,
  .update_entry = app_alias_update_entry,
  .write_map = app_alias_write_map,
  .resolve_user = app_alias_resolve_user,
  .resolve_action = app_alias_resolve_action,
  .execute = app_alias_execute
};

const AppAliasLib *get_app_alias_lib(void) {
  return &app_alias_instance;
}
