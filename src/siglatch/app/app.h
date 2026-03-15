/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_H
#define SIGLATCH_SERVER_APP_H

#include "config/config.h"
#include "daemon/daemon.h"
#include "help/help.h"
#include "inbound/inbound.h"
#include "keys/keys.h"
#include "opts/opts.h"
#include "packet/packet.h"
#include "payload/payload.h"
#include "runtime/runtime.h"
#include "server/server.h"
#include "signal/signal.h"
#include "startup/startup.h"
#include "udp/udp.h"

typedef struct {
  ConfigLib config;
  AppDaemonLib daemon;
  AppHelpLib help;
  AppInboundLib inbound;
  AppKeysLib keys;
  AppOptsLib opts;
  AppPacketLib packet;
  AppPayloadLib payload;
  AppRuntimeLib runtime;
  AppServerLib server;
  AppSignalLib signal;
  AppStartupLib startup;
  AppUdpLib udp;
} App;

extern App app;

int init_app(void);
void shutdown_app(void);

#endif
