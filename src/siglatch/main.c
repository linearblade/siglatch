/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>      
#include <stdlib.h>     
#include <string.h>     
#include <signal.h>     

#include "config.h"
//#include "config_debug.h"
#include "udp_listener.h"
#include "decrypt.h"
#include "shutdown.h"
#include "signal.h"
#include "daemon.h"
#include "start_opts.h"
#include "lib.h"

volatile sig_atomic_t should_exit = 0;


int main(int argc, char *argv[]) {
  init_signals();
  init_lib();
  lib.log.set_enabled(1);
  lib.log.set_debug(1);
  lib.log.set_level(LOG_TRACE);
  LOGE("🚀 Launching...\n");
  //siglatch_config *cfg = NULL;//    load_config("/etc/siglatch/config");
  
  lib.config.load("/etc/siglatch/config");
  //lib.config.dump();
  siglatch_config * cfg = (siglatch_config*) lib.config.get();

  if (!cfg){
    shutdown_config_error();
    exit(EXIT_FAILURE);
  }
  lib.config.set_current_server("secure");

  LOGT("loaded config\n");
  
  if (!start_opts(argc, argv, cfg) )
    exit(0);
  

  if (cfg && cfg->current_server && *cfg->current_server->log_file) {
    lib.log.open(cfg->current_server->log_file);
  }else {
    LOGW("⚠️  LOG FILE NOT DEFINED IN CONFIG — logging disabled.\n");
    lib.log.set_enabled(0);
  }

  int sock = start_udp_listener(cfg);
  if (sock < 0) shutdown_socket_error(cfg);
  siglatch_daemon(cfg, sock);
  
  return shutdown_OK(cfg,sock);
}

