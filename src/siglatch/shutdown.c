#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "shutdown.h"
#include "help.h"
#include "lib.h"
int shutdown_config_error(){
  LOGE( "❌ Failed to load config\n");
  return 1;
}

void shutdown_socket_error(siglatch_config * cfg){
    LOGPERR( "❌ Socket creation failed");
    //free_config(cfg);
    shutdown_lib();
    exit(EXIT_FAILURE);
}

int shutdown_OK(siglatch_config * cfg, int sock){
  if (sock >= 0)
    close(sock);
  shutdown_lib();
  //free_config(cfg);
  LOGW("✅ Shutdown complete\n");
  return 0;
}

int shutdown_bad_opts(siglatch_config *cfg, int argc, char *argv[]){
  if (argc > 1) {
    LOGE( "❌ Unknown option: %s\n", argv[1]);
  }
  siglatch_help(argc,argv);
  shutdown_lib();
  exit(EXIT_FAILURE);
}
