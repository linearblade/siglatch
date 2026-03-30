/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>

#include "help.h"

#include "../../lib.h"
#include "../version.h"

static int app_help_init(void) {
  return 1;
}

static void app_help_shutdown(void) {
}

static void app_help_show_version(void) {
  lib.log.console("siglatchd %s\n", SIGLATCH_SERVER_VERSION);
}

static void app_help_show(int argc, char *argv[]) {
  const char *progname = (argc > 0 && argv[0]) ? argv[0] : "siglatchd";

  app_help_show_version();
  lib.log.console("Usage: %s [--config <path>] [--dump-config] [--help] [--output-mode unicode|ascii] [--server <name>]\n",
                  progname);
  lib.log.console("Options:\n");
  lib.log.console("  --config          Override config file path\n");
  lib.log.console("  --dump-config     Print parsed configuration and exit\n");
  lib.log.console("  --help            Show this help message\n");
  lib.log.console("  --output-mode     Override output mode at runtime\n");
  lib.log.console("  --server          Select server block by name\n");
  lib.log.console("  --version         Print server version and exit\n");
}

static const AppHelpLib app_help_instance = {
  .init = app_help_init,
  .shutdown = app_help_shutdown,
  .version = app_help_show_version,
  .show = app_help_show
};

const AppHelpLib *get_app_help_lib(void) {
  return &app_help_instance;
}
