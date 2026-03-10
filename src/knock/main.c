/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "lib.h"
#include "parse_opts.h"
#include "app/app.h"

int main(int argc, char *argv[]) {
  int status = 1;
  Opts opts = {0};

  init_lib();
  init_app();

  app.output_mode.set_from_config();
  app.output_mode.set_from_env();

  if (!parseOpts(argc, argv, &opts) ){
    app.help.handleParseResult(argc, argv, &opts);
    goto cleanup;
  }

  app.output_mode.set_from_opts(&opts);
  lib.log.open(opts.log_file);
  lib.log.set_debug(opts.verbose?1:0);
  lib.log.set_level(opts.verbose);
  
  status = app.transmit.singlePacket(&opts);

cleanup:
  shutdown_app();
  shutdown_lib();
  return status;
}
