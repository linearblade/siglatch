/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_H
#define SIGLATCH_SERVER_APP_H

#include "builtin/builtin.h"
#include "config/config.h"
#include "daemon4/daemon4.h"
#include "help/help.h"
#include "inbound/inbound.h"
#include "keys/keys.h"
#include "object/object.h"
#include "opts/opts.h"
#include "payload/payload.h"
#include "policy/policy.h"
#include "runtime/runtime.h"
#include "server/server.h"
#include "signal/signal.h"
#include "workspace/workspace.h"
#include "startup/startup.h"
#include "udp/udp.h"

typedef struct {
  AppBuiltinLib builtin;
  ConfigLib config;
  AppDaemon4 daemon4;
  AppHelpLib help;
  AppInboundLib inbound;
  AppKeysLib keys;
  AppObjectLib object;
  AppOptsLib opts;
  AppPayloadLib payload;
  AppPolicyLib policy;
  AppRuntimeLib runtime;
  AppServerLib server;
  AppSignalLib signal;
  AppWorkspaceLib workspace;
  AppStartupLib startup;
  AppUdpLib udp;
} App;

extern App app;

int init_app(void);
void shutdown_app(void);

#endif
