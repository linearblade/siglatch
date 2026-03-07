/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include "help.h"
#include "lib.h"
void siglatch_help(int argc, char *argv[]) {
    const char *progname = (argc > 0 && argv[0]) ? argv[0] : "siglatchd";

    lib.log.console( "Usage: %s [--dump-config] [--help] [--output-mode unicode|ascii] [--server <name>]\n", progname);
    lib.log.console( "Options:\n");
    lib.log.console( "  --dump-config     Print parsed configuration and exit\n");
    lib.log.console( "  --help            Show this help message\n");
    lib.log.console( "  --output-mode     Override output mode at runtime\n");
    lib.log.console( "  --server          Select server block by name\n");
}
