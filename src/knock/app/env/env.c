/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "env.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../lib.h"

#define KNOCKER_CLIENT_CONFIG_DIR ".config/siglatch"
#define KNOCKER_CLIENT_CONFIG_FILE "client.conf"
#define KNOCKER_CLIENT_OUTPUT_MODE_KEY "output_mode"
#define KNOCKER_HOST_USER_CONFIG_PREFIX "client."
#define KNOCKER_HOST_USER_CONFIG_SUFFIX ".conf"
#define KNOCKER_HOST_SEND_FROM_KEY "send_from_ip"

static const char *app_env_home_or_error(void);
static char *trim_ws(char *value);
static int app_env_build_config_root_path(char *out, size_t out_size);
static int build_client_config_dir_path(char *out, size_t out_size);
static int build_client_config_file_path(char *out, size_t out_size);
static int ensure_client_config_dir_exists(void);
static int app_env_user_token_valid(const char *user);
static int app_env_build_host_user_config_filename(char *out, size_t out_size, const char *user);
static int app_env_load_host_user_send_from_ip(const char *host, const char *user, char *out, size_t out_size);
static int app_env_save_host_user_send_from_ip(const char *host, const char *user, const char *ip);
static int app_env_clear_host_user_send_from_ip(const char *host, const char *user);

static int app_env_init(void) {
  return 1;
}

static void app_env_shutdown(void) {
}

static const char *app_env_home_or_error(void) {
  const char *home = NULL;

  if (!lib.env.user.home || !lib.env.user.home(&home)) {
    lib.print.uc_fprintf(stderr, "err", "HOME environment variable not set\n");
    return NULL;
  }

  return home;
}

static char *trim_ws(char *value) {
  char *end;

  if (!value) {
    return NULL;
  }

  while (*value != '\0' && isspace((unsigned char)*value)) {
    value++;
  }

  if (*value == '\0') {
    return value;
  }

  end = value + strlen(value) - 1;
  while (end > value && isspace((unsigned char)*end)) {
    *end = '\0';
    end--;
  }

  return value;
}

static int app_env_build_config_root_path(char *out, size_t out_size) {
  const char *home = NULL;
  int written = 0;

  if (!out || out_size == 0) {
    return 0;
  }

  home = app_env_home_or_error();
  if (!home) {
    return 0;
  }

  written = snprintf(out, out_size, "%s/%s", home, KNOCKER_CLIENT_CONFIG_DIR);
  if (written < 0 || (size_t)written >= out_size) {
    lib.print.uc_fprintf(stderr, "err", "Config root path too long\n");
    return 0;
  }

  return 1;
}

static int app_env_build_host_config_path(char *out, size_t out_size, const char *host, const char *filename) {
  char root_path[PATH_MAX] = {0};
  int written = 0;

  if (!out || out_size == 0 || !host || !*host) {
    lib.print.uc_fprintf(stderr, "err", "Invalid host config path request\n");
    return 0;
  }

  if (!app_env_build_config_root_path(root_path, sizeof(root_path))) {
    return 0;
  }

  if (filename && *filename) {
    written = snprintf(out, out_size, "%s/%s/%s", root_path, host, filename);
  } else {
    written = snprintf(out, out_size, "%s/%s", root_path, host);
  }

  if (written < 0 || (size_t)written >= out_size) {
    lib.print.uc_fprintf(stderr, "err", "Config path too long for host '%s'\n", host);
    return 0;
  }

  return 1;
}

static int app_env_ensure_host_config_dir(const char *host) {
  char path[PATH_MAX] = {0};

  if (!ensure_client_config_dir_exists()) {
    return 0;
  }

  if (!app_env_build_host_config_path(path, sizeof(path), host, NULL)) {
    return 0;
  }

  if (!lib.env.user.ensure_dir || !lib.env.user.ensure_dir(path, 0700)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to create directory: %s (%s)\n",
                         path, strerror(errno));
    return 0;
  }

  return 1;
}

static int build_client_config_dir_path(char *out, size_t out_size) {
  return app_env_build_config_root_path(out, out_size);
}

static int build_client_config_file_path(char *out, size_t out_size) {
  char dir_path[PATH_MAX];
  int written = 0;

  if (!build_client_config_dir_path(dir_path, sizeof(dir_path))) {
    return 0;
  }

  written = snprintf(out, out_size, "%s/%s", dir_path, KNOCKER_CLIENT_CONFIG_FILE);
  if (written < 0 || (size_t)written >= out_size) {
    lib.print.uc_fprintf(stderr, "err", "Client config file path too long\n");
    return 0;
  }

  return 1;
}

static int ensure_client_config_dir_exists(void) {
  char dir_path[PATH_MAX];

  if (!lib.env.user.ensure_home_config_dir || !lib.env.user.ensure_home_config_dir()) {
    lib.print.uc_fprintf(stderr, "err",
                         "Failed to ensure home config directory (~/.config) (%s)\n",
                         strerror(errno));
    return 0;
  }

  if (!build_client_config_dir_path(dir_path, sizeof(dir_path))) {
    return 0;
  }

  if (!lib.env.user.ensure_dir || !lib.env.user.ensure_dir(dir_path, 0700)) {
    lib.print.uc_fprintf(stderr, "err", "Failed to create config directory: %s (%s)\n",
                         dir_path, strerror(errno));
    return 0;
  }

  return 1;
}

static int app_env_user_token_valid(const char *user) {
  size_t i = 0;

  if (!user || !user[0]) {
    return 0;
  }

  for (i = 0; user[i] != '\0'; ++i) {
    unsigned char ch = (unsigned char)user[i];
    if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '.')) {
      return 0;
    }
  }

  return 1;
}

static int app_env_build_host_user_config_filename(char *out, size_t out_size, const char *user) {
  int written = 0;

  if (!out || out_size == 0 || !app_env_user_token_valid(user)) {
    return 0;
  }

  written = snprintf(out, out_size, "%s%s%s",
                     KNOCKER_HOST_USER_CONFIG_PREFIX,
                     user,
                     KNOCKER_HOST_USER_CONFIG_SUFFIX);
  if (written < 0 || (size_t)written >= out_size) {
    return 0;
  }

  return 1;
}

static int app_env_load_output_mode_default(void) {
  char config_path[PATH_MAX];
  char line[256];
  FILE *fp = NULL;

  if (!build_client_config_file_path(config_path, sizeof(config_path))) {
    return 0;
  }

  fp = fopen(config_path, "r");
  if (!fp) {
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *entry = trim_ws(line);
    char *equals = NULL;
    char *key = NULL;
    char *value = NULL;
    int mode = 0;

    if (!entry || *entry == '\0' || *entry == '#' || *entry == ';') {
      continue;
    }

    equals = strchr(entry, '=');
    if (!equals) {
      continue;
    }

    *equals = '\0';
    key = trim_ws(entry);
    value = trim_ws(equals + 1);
    if (!key || !value) {
      continue;
    }

    if (strcmp(key, KNOCKER_CLIENT_OUTPUT_MODE_KEY) != 0) {
      continue;
    }

    mode = lib.print.output_parse_mode(value);
    if (!mode) {
      lib.print.uc_fprintf(stderr, "warn",
                           "Invalid output_mode in %s: %s (expected 'unicode' or 'ascii')\n",
                           config_path, value);
      fclose(fp);
      return 0;
    }

    fclose(fp);
    return mode;
  }

  fclose(fp);
  return 0;
}

static int app_env_load_host_user_send_from_ip(const char *host, const char *user,
                                               char *out, size_t out_size) {
  char filename[PATH_MAX];
  char config_path[PATH_MAX];
  char line[256];
  FILE *fp = NULL;

  if (!out || out_size == 0 || !host || !host[0] || !app_env_user_token_valid(user)) {
    return -1;
  }

  out[0] = '\0';

  if (!app_env_build_host_user_config_filename(filename, sizeof(filename), user)) {
    return -1;
  }

  if (!app_env_build_host_config_path(config_path, sizeof(config_path), host, filename)) {
    return -1;
  }

  fp = fopen(config_path, "r");
  if (!fp) {
    if (errno == ENOENT) {
      return 0;
    }
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *entry = trim_ws(line);
    char *equals = NULL;
    char *key = NULL;
    char *value = NULL;

    if (!entry || *entry == '\0' || *entry == '#' || *entry == ';') {
      continue;
    }

    equals = strchr(entry, '=');
    if (!equals) {
      continue;
    }

    *equals = '\0';
    key = trim_ws(entry);
    value = trim_ws(equals + 1);
    if (!key || !value) {
      continue;
    }

    if (strcmp(key, KNOCKER_HOST_SEND_FROM_KEY) != 0) {
      continue;
    }

    if (!lib.net.ip.range.is_single_ipv4(value)) {
      fclose(fp);
      return -1;
    }

    lib.str.lcpy(out, value, out_size);
    fclose(fp);
    return 1;
  }

  fclose(fp);
  return 0;
}

static int app_env_save_host_user_send_from_ip(const char *host,
                                               const char *user,
                                               const char *ip) {
  char filename[PATH_MAX];
  char config_path[PATH_MAX];
  FILE *fp = NULL;

  if (!host || !host[0] || !app_env_user_token_valid(user) ||
      !ip || !lib.net.ip.range.is_single_ipv4(ip)) {
    return 0;
  }

  if (!app_env_ensure_host_config_dir(host)) {
    return 0;
  }

  if (!app_env_build_host_user_config_filename(filename, sizeof(filename), user)) {
    return 0;
  }

  if (!app_env_build_host_config_path(config_path, sizeof(config_path), host, filename)) {
    return 0;
  }

  fp = fopen(config_path, "w");
  if (!fp) {
    lib.print.uc_fprintf(stderr, "err",
                         "Failed to write host user config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  if (fprintf(fp, "%s = %s\n", KNOCKER_HOST_SEND_FROM_KEY, ip) < 0) {
    fclose(fp);
    lib.print.uc_fprintf(stderr, "err",
                         "Failed to write host user config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  if (fclose(fp) != 0) {
    lib.print.uc_fprintf(stderr, "err",
                         "Failed to close host user config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  if (chmod(config_path, 0600) != 0) {
    lib.print.uc_fprintf(stderr, "warn",
                         "Could not chmod %s to 0600 (%s)\n",
                         config_path, strerror(errno));
  }

  lib.print.uc_printf("ok",
                      "Saved send_from_ip '%s' for %s/%s in %s\n",
                      ip, host, user, config_path);
  return 1;
}

static int app_env_clear_host_user_send_from_ip(const char *host, const char *user) {
  char filename[PATH_MAX];
  char config_path[PATH_MAX];

  if (!host || !host[0] || !app_env_user_token_valid(user)) {
    return 0;
  }

  if (!app_env_build_host_user_config_filename(filename, sizeof(filename), user)) {
    return 0;
  }

  if (!app_env_build_host_config_path(config_path, sizeof(config_path), host, filename)) {
    return 0;
  }

  if (unlink(config_path) != 0) {
    if (errno == ENOENT) {
      lib.print.uc_printf("warn",
                          "No send_from_ip default was set for %s/%s\n",
                          host, user);
      return 1;
    }

    lib.print.uc_fprintf(stderr, "err",
                         "Failed to clear host user config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  lib.print.uc_printf("ok",
                      "Cleared send_from_ip default for %s/%s\n",
                      host, user);
  return 1;
}

static int app_env_save_output_mode_default(const char *mode_value) {
  int mode = lib.print.output_parse_mode(mode_value);
  const char *mode_name = NULL;
  char config_path[PATH_MAX];
  FILE *fp = NULL;

  if (!mode) {
    lib.print.uc_fprintf(stderr, "err",
                         "Invalid output mode default: %s (expected 'unicode' or 'ascii')\n",
                         mode_value ? mode_value : "(null)");
    return 0;
  }

  mode_name = lib.print.output_mode_name(mode);
  if (!mode_name || strcmp(mode_name, "unknown") == 0) {
    lib.print.uc_fprintf(stderr, "err", "Unable to resolve output mode name for value: %d\n", mode);
    return 0;
  }

  if (!ensure_client_config_dir_exists()) {
    return 0;
  }

  if (!build_client_config_file_path(config_path, sizeof(config_path))) {
    return 0;
  }

  fp = fopen(config_path, "w");
  if (!fp) {
    lib.print.uc_fprintf(stderr, "err", "Failed to write client config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  fprintf(fp, "# Siglatch knocker client defaults\n");
  fprintf(fp, "%s=%s\n", KNOCKER_CLIENT_OUTPUT_MODE_KEY, mode_name);

  if (fclose(fp) != 0) {
    lib.print.uc_fprintf(stderr, "err", "Failed to close client config: %s (%s)\n",
                         config_path, strerror(errno));
    return 0;
  }

  if (chmod(config_path, 0600) != 0) {
    lib.print.uc_fprintf(stderr, "warn", "Failed to set config permissions on %s (%s)\n",
                         config_path, strerror(errno));
  }

  lib.print.uc_printf("ok", "Saved default output mode '%s' to %s\n", mode_name, config_path);
  return 1;
}

static const AppEnvLib app_env_instance = {
  .init = app_env_init,
  .shutdown = app_env_shutdown,
  .build_config_root_path = app_env_build_config_root_path,
  .build_host_config_path = app_env_build_host_config_path,
  .ensure_host_config_dir = app_env_ensure_host_config_dir,
  .load_host_user_send_from_ip = app_env_load_host_user_send_from_ip,
  .save_host_user_send_from_ip = app_env_save_host_user_send_from_ip,
  .clear_host_user_send_from_ip = app_env_clear_host_user_send_from_ip,
  .load_output_mode_default = app_env_load_output_mode_default,
  .save_output_mode_default = app_env_save_output_mode_default
};

const AppEnvLib *get_app_env_lib(void) {
  return &app_env_instance;
}
