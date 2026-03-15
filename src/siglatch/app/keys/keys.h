/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_KEYS_H
#define SIGLATCH_SERVER_APP_KEYS_H

#include "master.h"
#include "user.h"
#include "server.h"
#include "hmac.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*load)(siglatch_config *cfg);
  AppKeysMasterLib master;
  AppKeysUserLib user;
  AppKeysServerLib server;
  AppKeysHmacLib hmac;
} AppKeysLib;

const AppKeysLib *get_app_keys_lib(void);

#endif
