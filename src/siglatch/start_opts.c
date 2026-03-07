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
    int show_dump = 0;
    int show_help = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--dump-config") == 0) {
            show_dump = 1;
            continue;
        }

        if (strcmp(argv[i], "--help") == 0) {
            show_help = 1;
            continue;
        }

        if (strcmp(argv[i], "--output-mode") == 0) {
            if (i + 1 >= argc) {
                shutdown_bad_opts(cfg, argc, argv);
                return 0;
            }

            {
                int mode = lib.print.output_parse_mode(argv[i + 1]);
                if (!mode) {
                    LOGE("Invalid --output-mode '%s' (expected 'unicode' or 'ascii')\n", argv[i + 1]);
                    shutdown_bad_opts(cfg, argc, argv);
                    return 0;
                }

                lib.print.output_set_mode(mode);
            }
            i++;
            continue;
        }

        if (strcmp(argv[i], "--server") == 0) {
            const char *server_name = NULL;
            char err_buf[160];

            if (i + 1 >= argc) {
                shutdown_bad_opts_msg(cfg, argc, argv, "Missing value for --server");
                return 0;
            }

            server_name = argv[i + 1];
            if (!server_name || server_name[0] == '\0') {
                shutdown_bad_opts_msg(cfg, argc, argv, "Invalid --server value (empty)");
                return 0;
            }

            if (!lib.config.set_current_server(server_name)) {
                snprintf(err_buf, sizeof(err_buf), "Unknown or disabled server: %s", server_name);
                shutdown_bad_opts_msg(cfg, argc, argv, err_buf);
                return 0;
            }

            i++;
            continue;
        }

        shutdown_bad_opts(cfg, argc, argv);
        return 0;
    }

    if (show_help) {
        siglatch_help(argc, argv);
        shutdown_OK(cfg, -1);
        return 0;
    }

    if (show_dump) {
        lib.config.dump();
        shutdown_OK(cfg, -1);
        return 0;
    }

    return 1;  // continue with daemon startup
}
