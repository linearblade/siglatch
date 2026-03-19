/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "user.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

static void process_user_init(void);
static void process_user_shutdown(void);
static int process_user_lookup_by_name(const char *name, ProcessUserIdentity *out);
static int process_user_drop_to_name(const char *name);
static int process_user_drop_to_identity(const ProcessUserIdentity *identity);

static const ProcessUserLib process_user_instance = {
  .init = process_user_init,
  .shutdown = process_user_shutdown,
  .lookup_by_name = process_user_lookup_by_name,
  .drop_to_name = process_user_drop_to_name,
  .drop_to_identity = process_user_drop_to_identity
};

static void process_user_init(void) {
}

static void process_user_shutdown(void) {
}

static int process_user_lookup_by_name(const char *name, ProcessUserIdentity *out) {
  struct passwd *pwd = NULL;

  if (!name || name[0] == '\0' || !out) {
    return 0;
  }

  pwd = getpwnam(name);
  if (!pwd) {
    return 0;
  }

  memset(out, 0, sizeof(*out));
  out->uid = pwd->pw_uid;
  out->gid = pwd->pw_gid;
  strncpy(out->name, pwd->pw_name, sizeof(out->name) - 1);
  out->name[sizeof(out->name) - 1] = '\0';
  return 1;
}

static int process_user_drop_to_name(const char *name) {
  ProcessUserIdentity identity = {0};

  if (!process_user_lookup_by_name(name, &identity)) {
    return 0;
  }

  return process_user_drop_to_identity(&identity);
}

static int process_user_drop_to_identity(const ProcessUserIdentity *identity) {
  if (!identity || identity->name[0] == '\0') {
    errno = EINVAL;
    return 0;
  }

  if (geteuid() != 0) {
    if (geteuid() == identity->uid && getegid() == identity->gid) {
      return 1;
    }

    errno = EPERM;
    return 0;
  }

  if (initgroups(identity->name, identity->gid) != 0) {
    return 0;
  }

  if (setgid(identity->gid) != 0) {
    return 0;
  }

  if (setuid(identity->uid) != 0) {
    return 0;
  }

  return 1;
}

const ProcessUserLib *get_lib_process_user(void) {
  return &process_user_instance;
}
