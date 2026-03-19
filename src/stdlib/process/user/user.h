/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_PROCESS_USER_H
#define SIGLATCH_PROCESS_USER_H

#include <sys/types.h>

typedef struct {
  uid_t uid;
  gid_t gid;
  char name[64];
} ProcessUserIdentity;

typedef struct {
  void (*init)(void);
  void (*shutdown)(void);
  int (*lookup_by_name)(const char *name, ProcessUserIdentity *out);
  int (*drop_to_name)(const char *name);
  int (*drop_to_identity)(const ProcessUserIdentity *identity);
} ProcessUserLib;

const ProcessUserLib *get_lib_process_user(void);

#endif /* SIGLATCH_PROCESS_USER_H */
