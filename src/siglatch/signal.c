#include "signal.h"
#include "lib.h"
void init_signals(){
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
}


void handle_signal(int sig) {
    should_exit = 1;
    LOGT("\n🛑 Caught signal %d — shutting down...\n", sig);
}
