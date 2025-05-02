
#ifndef SIGLATCH_SHUTDOWN_H
#define SIGLATCH_SHUTDOWN_H

#include <signal.h>
#include "config.h"

extern volatile sig_atomic_t should_exit;

int shutdown_config_error();
void shutdown_socket_error(siglatch_config *cfg);
int shutdown_OK(siglatch_config *cfg, int sock);
int shutdown_bad_opts(siglatch_config *cfg, int argc, char *argv[]);

#endif // SIGLATCH_SHUTDOWN_H
