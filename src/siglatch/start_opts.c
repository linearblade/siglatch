/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
//#include "config_debug.h"
#include "shutdown.h"
#include "start_opts.h"
#include "help.h"
#include "lib.h"

int start_opts(int argc, char *argv[], siglatch_config *cfg) {
    if (argc > 1) {
        if (strcmp(argv[1], "--dump-config") == 0) {
	  lib.config.dump();
            shutdown_OK(cfg, -1);
	    return(0);
        } else if (strcmp(argv[1], "--help") == 0) {
            siglatch_help(argc, argv);
	    shutdown_OK(cfg, -1);
	    return(0);
        } else {
            shutdown_bad_opts(cfg, argc, argv);
	    return(0);
        }
    }
    return 1;  // continue with daemon startup
}
