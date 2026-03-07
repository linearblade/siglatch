/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lib.h"
#include "main_helpers.h"
#include "../stdlib/utils.h" // my temporary trash bin for shit that goes to relevant places later.
#include "../stdlib/hmac_key.h"  // for lib.hmac
#include "../stdlib/openssl_session.h"
#include "parse_opts.h"
#include "print_help.h"

#define PORT 50000
#define TARGET "127.0.0.1"
#define PUBKEY_PATH "~/.config/siglatch/server_pub.pem"
#define USER_PRIKEY_PATH "~/.config/siglatch/keys/localhost.root.pri.pem"
#define USER_HMACKEY_PATH "~/.config/siglatch/keys/localhost.root.hmac.key"

#include <openssl/hmac.h>  // for HMAC
#include <string.h>        // for memcpy, memset
int transmit(Opts *opts);


#define FAIL_TRANSMIT(...) if(1) {		\
    if (lib.log.emit) {				\
      lib.log.emit(LOG_ERROR, 1, __VA_ARGS__);	\
    }						\
    break;					\
  } 

int main(int argc, char *argv[]) {
  int status = 1;
  Opts opts = {0};

  init_lib();

  {
    int config_output_mode = opts_load_output_mode_default();
    if (config_output_mode) {
      lib.print.output_set_mode(config_output_mode);
    }
  }

  {
    const char *env_output_value = getenv("SIGLATCH_OUTPUT_MODE");
    int env_output_mode = lib.print.output_parse_mode(env_output_value);
    if (env_output_mode) {
      lib.print.output_set_mode(env_output_mode);
    } else if (env_output_value && *env_output_value) {
      fprintf(stderr,
              "Invalid SIGLATCH_OUTPUT_MODE '%s' (expected 'unicode' or 'ascii')\n",
              env_output_value);
    }
  }

  if (!parseOpts(argc, argv, &opts) ){
    if (argc < 2 || (argc > 1 && strncmp(argv[1], "--help", 6) == 0)) {
      printHelp();
    } else {
      fprintf(stderr, "Use --help for usage.\n");
    }
    goto cleanup;
  }
  lib.log.open(opts.log_file);
  lib.log.set_debug(opts.verbose?1:0);
  lib.log.set_level(opts.verbose);
  
  status = transmit(&opts);

cleanup:
  shutdown_lib();
  return status;
    
}

/*
  
1/ hmac key- 
2/ server key (aka pub key)
3/ client key (aka client private key for receiving)
4/ config dir (will use this to pull all the data)
5/ hmac transmission : true (default) ,false , dummy
6/ encrypt true false
7/ dead drop | true | false
8/ action map file

command line 
./<program> host command payload
payload should have an pipe in from stdout or whatever, and optional type it in mode

OR
./<program> --alias action_name action_id

 */

int transmit(Opts *opts){
  int status = 1; //assume fail
  SiglatchOpenSSLSession session = {0};
  do {

    // --  Here: Build KnockPacket --
    KnockPacket pkt = {0};
    if (!structurePacket(&pkt, opts->payload, opts->payload_len, opts->user_id, opts->action_id)) {
      FAIL_TRANSMIT("Failed to structure packet");
    }
    
    if (!init_user_openssl_session(opts, &session)) {
      FAIL_TRANSMIT("Failed to initialize OpenSSL session\n");
    }
	
    // --  Then sign --
    if (!signWrapper(opts,&session, &pkt) ){
      FAIL_TRANSMIT("Failed to sign packet\n");
    }

    // --  Then pack it --
    uint8_t packed[512] = {0};
    int packed_len = lib.payload.pack(&pkt, packed, sizeof(packed));
    if (!structureOrDeadDrop(opts, &pkt, packed, &packed_len)) {
      FAIL_TRANSMIT("Failed to prepare payload (structured or dead-drop)");
    }
    
    // --  Then encrypt --
    unsigned char data[512] = {0};
    size_t data_len = 0;

    if (!encryptWrapper(opts, &session, packed, packed_len, data, &data_len)) {
      FAIL_TRANSMIT("Failed to prepare payload (encryption or raw mode)");
    }

    // --  Then send it --
    char ip[INET_ADDRSTRLEN];
    int rv = lib.net.resolve_host_to_ip(opts->host, ip, sizeof(ip));

    switch (rv) {
    case 1:
      break;
    case -2:
      FAIL_TRANSMIT("Hostname is NULL");
      break;
    case -3:
      FAIL_TRANSMIT("Output buffer is NULL");
      break;
    default:
      FAIL_TRANSMIT("Could not resolve hostname: %s", opts->host);
      break;
    }
    
    if (!lib.udp.send(ip, opts->port, data, data_len)) {
      FAIL_TRANSMIT("Failed to send UDP packet\n");
    }

    status = 0; // Success!

  } while (0);
  lib.openssl.session_free(&session);
  return status;
}
