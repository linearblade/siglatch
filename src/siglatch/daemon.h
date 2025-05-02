
#ifndef SIGLATCH_DAEMON_H
#define SIGLATCH_DAEMON_H

#include "config.h"

void siglatch_daemon(siglatch_config *cfg, int sock);
#define SL_EXIT_ERR_NETWORK_FATAL 3
#endif // SIGLATCH_DAEMON_H
