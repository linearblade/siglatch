/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "ops.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../lib.h"
#include "../app.h"

static int app_alias_ops_init(void) {
  return 1;
}

static void app_alias_ops_shutdown(void) {
}

static int app_alias_ops_set_user(const char *host, const char *user, uint32_t user_id) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;
  int ok = 0;

  if (!host || !*host || !user || !*user || user_id == 0) {
    lib.print.uc_fprintf(stderr, "err", "Invalid arguments for user alias set\n");
    return 0;
  }

  if (!app.env.ensure_host_config_dir(host)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to ensure host directory: %s\n", host);
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "user.map")) {
    return 0;
  }

  if (access(path, F_OK) == 0 && !app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read existing alias file: %s\n", path);
    return 0;
  }

  if (!app.alias.update_entry(&aliases, &alias_count, user, host, user_id)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to update alias entry in memory\n");
    goto cleanup;
  }

  if (!app.alias.write_map(path, aliases, alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to write alias map back to disk: %s\n", path);
    goto cleanup;
  }

  lib.print.uc_printf("ok", "User alias updated successfully: %s -> %s (id=%u)\n", user, host, user_id);
  ok = 1;

cleanup:
  free(aliases);
  return ok;
}

static int app_alias_ops_set_action(const char *host, const char *action, uint32_t action_id) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;
  int ok = 0;

  if (!host || !*host || !action || !*action || action_id == 0) {
    lib.print.uc_fprintf(stderr, "err", "Invalid arguments for action alias set\n");
    return 0;
  }

  if (!app.env.ensure_host_config_dir(host)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to ensure host directory: %s\n", host);
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "action.map")) {
    return 0;
  }

  if (access(path, F_OK) == 0 && !app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read existing alias file: %s\n", path);
    return 0;
  }

  if (!app.alias.update_entry(&aliases, &alias_count, action, host, action_id)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to update alias entry in memory\n");
    goto cleanup;
  }

  if (!app.alias.write_map(path, aliases, alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to write alias map back to disk: %s\n", path);
    goto cleanup;
  }

  lib.print.uc_printf("ok", "Action alias updated successfully: %s -> %s (id=%u)\n", action, host, action_id);
  ok = 1;

cleanup:
  free(aliases);
  return ok;
}

static int app_alias_ops_show_user(const char *host) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;

  if (!host || !*host) {
    lib.print.uc_fprintf(stderr, "err", "Missing host for user alias show\n");
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "user.map")) {
    return 0;
  }

  if (access(path, F_OK) != 0) {
    lib.print.uc_fprintf(stderr, "err", "No user aliases found for host: %s\n", host);
    return 0;
  }

  if (!app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read user alias map: %s\n", path);
    return 0;
  }

  lib.print.uc_printf("users", "User Aliases for %s:\n", host);
  for (size_t i = 0; i < alias_count; i++) {
    printf("  - %s -> %s (id=%u)\n", aliases[i].name, aliases[i].host, aliases[i].id);
  }

  if (alias_count == 0) {
    printf("  (No user aliases found)\n");
  }

  free(aliases);
  return 1;
}

static int app_alias_ops_delete_user(const char *host, const char *user) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;
  int found = 0;
  size_t new_count = 0;
  int ok = 0;

  if (!host || !*host || !user || !*user) {
    lib.print.uc_fprintf(stderr, "err", "Invalid arguments for user alias delete\n");
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "user.map")) {
    return 0;
  }

  if (access(path, F_OK) != 0) {
    lib.print.uc_fprintf(stderr, "err", "User alias map does not exist: %s\n", path);
    return 0;
  }

  if (!app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read user alias map: %s\n", path);
    return 0;
  }

  for (size_t i = 0; i < alias_count; i++) {
    if (strcmp(aliases[i].name, user) == 0) {
      found = 1;
      continue;
    }
    aliases[new_count++] = aliases[i];
  }

  if (!found) {
    lib.print.uc_fprintf(stderr, "warn", "Alias not found for user: %s\n", user);
    goto cleanup;
  }

  if (!app.alias.write_map(path, aliases, new_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to write updated alias map after deletion\n");
    goto cleanup;
  }

  lib.print.uc_printf("del", "Deleted user alias: %s -> %s\n", user, host);
  ok = 1;

cleanup:
  free(aliases);
  return ok;
}

static int app_alias_ops_show_action(const char *host) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;

  if (!host || !*host) {
    lib.print.uc_fprintf(stderr, "err", "Missing host for action alias show\n");
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "action.map")) {
    return 0;
  }

  if (access(path, F_OK) != 0) {
    lib.print.uc_fprintf(stderr, "err", "No action aliases found for host: %s\n", host);
    return 0;
  }

  if (!app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read action alias map: %s\n", path);
    return 0;
  }

  lib.print.uc_printf("target", "Action Aliases for %s:\n", host);
  for (size_t i = 0; i < alias_count; i++) {
    printf("  - %s -> %s (id=%u)\n", aliases[i].name, aliases[i].host, aliases[i].id);
  }

  if (alias_count == 0) {
    printf("  (No action aliases found)\n");
  }

  free(aliases);
  return 1;
}

static int app_alias_ops_delete_action(const char *host, const char *action) {
  char path[PATH_MAX] = {0};
  AliasEntry *aliases = NULL;
  size_t alias_count = 0;
  int found = 0;
  size_t new_count = 0;
  int ok = 0;

  if (!host || !*host || !action || !*action) {
    lib.print.uc_fprintf(stderr, "err", "Invalid arguments for action alias delete\n");
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, "action.map")) {
    return 0;
  }

  if (access(path, F_OK) != 0) {
    lib.print.uc_fprintf(stderr, "err", "Action alias map does not exist: %s\n", path);
    return 0;
  }

  if (!app.alias.read_map(path, &aliases, &alias_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to read action alias map: %s\n", path);
    return 0;
  }

  for (size_t i = 0; i < alias_count; i++) {
    if (strcmp(aliases[i].name, action) == 0) {
      found = 1;
      continue;
    }
    aliases[new_count++] = aliases[i];
  }

  if (!found) {
    lib.print.uc_fprintf(stderr, "warn", "Alias not found for action: %s\n", action);
    goto cleanup;
  }

  if (!app.alias.write_map(path, aliases, new_count)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to write updated alias map after deletion\n");
    goto cleanup;
  }

  lib.print.uc_printf("del", "Deleted action alias: %s -> %s\n", action, host);
  ok = 1;

cleanup:
  free(aliases);
  return ok;
}

static int alias_entry_is_host_dir(const char *base_path, const char *entry_name) {
  char path[PATH_MAX] = {0};
  struct stat st;
  int written = 0;

  if (!base_path || !entry_name || !*entry_name) {
    return 0;
  }

  written = snprintf(path, sizeof(path), "%s/%s", base_path, entry_name);
  if (written < 0 || (size_t)written >= sizeof(path)) {
    return 0;
  }

  if (stat(path, &st) != 0) {
    return 0;
  }

  return S_ISDIR(st.st_mode) ? 1 : 0;
}

static int alias_host_has_map(const char *base_path, const char *entry_name, const char *map_filename) {
  char path[PATH_MAX] = {0};
  int written = 0;

  if (!base_path || !entry_name || !*entry_name || !map_filename || !*map_filename) {
    return 0;
  }

  written = snprintf(path, sizeof(path), "%s/%s/%s", base_path, entry_name, map_filename);
  if (written < 0 || (size_t)written >= sizeof(path)) {
    return 0;
  }

  return access(path, F_OK) == 0 ? 1 : 0;
}

typedef int (*AliasShowOneFn)(const char *host);

static int app_alias_ops_show_all(AliasShowOneFn show_one, const char *map_filename) {
  char base_path[PATH_MAX] = {0};
  DIR *dir = NULL;
  struct dirent *entry = NULL;
  int found_any = 0;
  size_t skipped_non_host = 0;

  if (!show_one || !map_filename || !*map_filename) {
    return 0;
  }

  if (!app.env.build_config_root_path(base_path, sizeof(base_path))) {
    return 0;
  }

  dir = opendir(base_path);
  if (!dir) {
    lib.print.uc_fprintf(stderr, "err", "Failed to open siglatch config directory: %s\n", base_path);
    return 0;
  }

  while ((entry = readdir(dir)) != NULL) {
    const char *name = entry->d_name;

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
      continue;
    }

    if (!alias_entry_is_host_dir(base_path, name)) {
      continue;
    }

    if (!alias_host_has_map(base_path, name, map_filename)) {
      skipped_non_host++;
      continue;
    }

    found_any = 1;
    printf("\n");
    if (!show_one(name)) {
      lib.print.uc_fprintf(stderr, "warn", "Failed to show aliases for host: %s\n", name);
    }
  }

  closedir(dir);

  if (!found_any) {
    lib.print.uc_printf("warn", "No hosts found under: %s\n", base_path);
  }

  if (skipped_non_host > 0) {
    lib.print.uc_printf("warn",
                        "Skipped %zu directories without %s under: %s\n",
                        skipped_non_host, map_filename, base_path);
  }

  return 1;
}

static int app_alias_ops_show_action_all(void) {
  return app_alias_ops_show_all(app_alias_ops_show_action, "action.map");
}

static int app_alias_ops_show_user_all(void) {
  return app_alias_ops_show_all(app_alias_ops_show_user, "user.map");
}

static int app_alias_ops_show_host(const char *host) {
  if (!host || !*host) {
    lib.print.uc_fprintf(stderr, "err", "Missing host for alias show\n");
    return 0;
  }

  printf("\n");
  if (!app_alias_ops_show_user(host)) {
    lib.print.uc_fprintf(stderr, "warn", "Failed to show user aliases for host: %s\n", host);
  }

  printf("\n");
  if (!app_alias_ops_show_action(host)) {
    lib.print.uc_fprintf(stderr, "warn", "Failed to show action aliases for host: %s\n", host);
  }

  return 1;
}

static int app_alias_ops_show_hosts(void) {
  char base_path[PATH_MAX] = {0};
  DIR *dir = NULL;
  struct dirent *entry = NULL;
  int found_any = 0;
  struct stat st;

  if (!app.env.build_config_root_path(base_path, sizeof(base_path))) {
    return 0;
  }

  if (stat(base_path, &st) != 0) {
    if (errno == ENOENT) {
      lib.print.uc_printf("warn", "No hosts setup yet.\n");
      return 1;
    }
    lib.print.uc_fprintf(stderr, "err", "Failed to stat siglatch config directory: %s (%s)\n",
                         base_path, strerror(errno));
    return 0;
  }

  if (!S_ISDIR(st.st_mode)) {
    lib.print.uc_fprintf(stderr, "err", "Siglatch config path is not a directory: %s\n", base_path);
    return 0;
  }

  dir = opendir(base_path);
  if (!dir) {
    lib.print.uc_fprintf(stderr, "err", "Failed to open siglatch config directory: %s\n", base_path);
    return 0;
  }

  lib.print.uc_printf("hosts", "Configured hosts:\n");

  while ((entry = readdir(dir)) != NULL) {
    const char *name = entry->d_name;

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
      continue;
    }

    if (!alias_entry_is_host_dir(base_path, name)) {
      continue;
    }

    if (!alias_host_has_map(base_path, name, "user.map") &&
        !alias_host_has_map(base_path, name, "action.map")) {
      continue;
    }

    found_any = 1;
    printf("  - %s\n", name);
  }

  closedir(dir);

  if (!found_any) {
    lib.print.uc_printf("warn", "No hosts setup yet.\n");
  }

  return 1;
}

static int app_alias_ops_delete_map_file(const char *host, const char *filename, const char *kind) {
  char path[PATH_MAX] = {0};

  if (!host || !*host || !filename || !*filename || !kind || !*kind) {
    return 0;
  }

  if (!app.env.build_host_config_path(path, sizeof(path), host, filename)) {
    return 0;
  }

  if (access(path, F_OK) != 0) {
    lib.print.uc_fprintf(stderr, "warn", "%s map file does not exist: %s\n", kind, path);
    return 0;
  }

  if (unlink(path) != 0) {
    lib.print.uc_fprintf(stderr, "err", "Failed to delete %s map file: %s (%s)\n", kind, path, strerror(errno));
    return 0;
  }

  lib.print.uc_printf("del", "Deleted %s map file for host: %s\n", kind, host);
  return 1;
}

static int app_alias_ops_delete_user_map(const char *host) {
  return app_alias_ops_delete_map_file(host, "user.map", "user");
}

static int app_alias_ops_delete_action_map(const char *host) {
  return app_alias_ops_delete_map_file(host, "action.map", "action");
}

static int app_alias_ops_delete_host(const char *host) {
  char base_path[PATH_MAX] = {0};
  char user_map_path[PATH_MAX] = {0};
  char action_map_path[PATH_MAX] = {0};
  int written = 0;
  int success = 1;

  if (!host || !*host) {
    lib.print.uc_fprintf(stderr, "err", "Missing host for alias delete\n");
    return 0;
  }

  if (!app.env.build_host_config_path(base_path, sizeof(base_path), host, NULL)) {
    return 0;
  }

  written = snprintf(user_map_path, sizeof(user_map_path), "%s/user.map", base_path);
  if (written < 0 || (size_t)written >= sizeof(user_map_path)) {
    lib.print.uc_fprintf(stderr, "err", "User alias file path too long for host: %s\n", host);
    return 0;
  }

  written = snprintf(action_map_path, sizeof(action_map_path), "%s/action.map", base_path);
  if (written < 0 || (size_t)written >= sizeof(action_map_path)) {
    lib.print.uc_fprintf(stderr, "err", "Action alias file path too long for host: %s\n", host);
    return 0;
  }

  if (access(user_map_path, F_OK) == 0) {
    if (unlink(user_map_path) != 0) {
      lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias file: %s (%s)\n",
                           user_map_path, strerror(errno));
      success = 0;
    } else {
      lib.print.uc_printf("del", "Deleted user alias file: %s\n", user_map_path);
    }
  } else {
    lib.print.uc_printf("warn", "User alias file does not exist: %s\n", user_map_path);
  }

  if (access(action_map_path, F_OK) == 0) {
    if (unlink(action_map_path) != 0) {
      lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias file: %s (%s)\n",
                           action_map_path, strerror(errno));
      success = 0;
    } else {
      lib.print.uc_printf("del", "Deleted action alias file: %s\n", action_map_path);
    }
  } else {
    lib.print.uc_printf("warn", "Action alias file does not exist: %s\n", action_map_path);
  }

  return success;
}

static const AppAliasOpsLib app_alias_ops_instance = {
  .init = app_alias_ops_init,
  .shutdown = app_alias_ops_shutdown,
  .set_user = app_alias_ops_set_user,
  .set_action = app_alias_ops_set_action,
  .show_user = app_alias_ops_show_user,
  .show_user_all = app_alias_ops_show_user_all,
  .delete_user = app_alias_ops_delete_user,
  .delete_user_map = app_alias_ops_delete_user_map,
  .show_action = app_alias_ops_show_action,
  .show_action_all = app_alias_ops_show_action_all,
  .delete_action = app_alias_ops_delete_action,
  .delete_action_map = app_alias_ops_delete_action_map,
  .show_host = app_alias_ops_show_host,
  .show_hosts = app_alias_ops_show_hosts,
  .delete_host = app_alias_ops_delete_host
};

const AppAliasOpsLib *get_app_alias_ops_lib(void) {
  return &app_alias_ops_instance;
}
