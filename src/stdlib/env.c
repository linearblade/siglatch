/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "env.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ENV_USER_HOME_CONFIG_DIR ".config"
#define ENV_USER_HOME_CONFIG_MODE 0755

static int env_user_build_home_path(char *out, size_t out_size, const char *relative_path);
static int env_user_ensure_dir(const char *path, mode_t mode);

static const char *env_get(const char *key) {
  if (!key || !*key) {
    errno = EINVAL;
    return NULL;
  }
  return getenv(key);
}

static int env_get_required(const char *key, const char **out) {
  const char *value = NULL;

  if (!out) {
    errno = EINVAL;
    return 0;
  }

  value = env_get(key);
  if (!value || !*value) {
    errno = ENOENT;
    return 0;
  }

  *out = value;
  return 1;
}

static int env_user_home(const char **out) {
  return env_get_required("HOME", out);
}

static int env_user_ensure_home_config_dir(void) {
  char path[PATH_MAX] = {0};

  if (!env_user_build_home_path(path, sizeof(path), ENV_USER_HOME_CONFIG_DIR)) {
    return 0;
  }

  return env_user_ensure_dir(path, ENV_USER_HOME_CONFIG_MODE);
}

static int env_user_build_home_path(char *out, size_t out_size, const char *relative_path) {
  const char *home = NULL;
  int written = 0;

  if (!out || out_size == 0) {
    errno = EINVAL;
    return 0;
  }

  if (!env_user_home(&home)) {
    return 0;
  }

  if (!relative_path || !*relative_path) {
    written = snprintf(out, out_size, "%s", home);
  } else if (relative_path[0] == '/') {
    written = snprintf(out, out_size, "%s%s", home, relative_path);
  } else {
    written = snprintf(out, out_size, "%s/%s", home, relative_path);
  }

  if (written < 0 || (size_t)written >= out_size) {
    errno = ENAMETOOLONG;
    return 0;
  }

  return 1;
}

static int env_user_ensure_dir(const char *path, mode_t mode) {
  struct stat st = {0};

  if (!path || !*path) {
    errno = EINVAL;
    return 0;
  }

  if (stat(path, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      return 0;
    }
    return 1;
  }

  if (mkdir(path, mode) != 0) {
    return 0;
  }

  return 1;
}

static int env_init(void) {
  return 1;
}

static void env_shutdown(void) {
}

static const EnvLib env_instance = {
  .init = env_init,
  .shutdown = env_shutdown,
  .core = {
    .get = env_get,
    .get_required = env_get_required
  },
  .user = {
    .home = env_user_home,
    .ensure_home_config_dir = env_user_ensure_home_config_dir,
    .build_home_path = env_user_build_home_path,
    .ensure_dir = env_user_ensure_dir
  }
};

const EnvLib *get_lib_env(void) {
  return &env_instance;
}
