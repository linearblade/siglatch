
#ifndef SIGLATCH_SIGNAL_H
#define SIGLATCH_SIGNAL_H

#include <signal.h>
#include "config.h"

extern volatile sig_atomic_t should_exit;

void handle_signal(int sig);
void init_signals();

#endif // SIGLATCH_SIGNAL_H
