/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef PARSE_OPTS_H
#define PARSE_OPTS_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h> // For PATH_MAX
#include "../stdlib/log.h" // for log level

typedef enum {
  HMAC_MODE_NONE = 0,   ///< No HMAC signing
  HMAC_MODE_NORMAL = 1, ///< Normal HMAC signing
  HMAC_MODE_DUMMY = 2   ///< Dummy HMAC (testing purposes)
} HmacMode;

typedef enum {
  OPTS_RESPONSE_HELP = 1,
  OPTS_RESPONSE_ERROR = 2,
  OPTS_RESPONSE_ALIAS = 3,
  OPTS_RESPONSE_TRANSMIT = 4
} OptsResponseType;



#define MAX_PAYLOAD_SIZE 200 // For now, simple fixed payload size

/**
 * Opts - fully resolved runtime options for transmission.
 */


typedef struct {
  // Paths
  char hmac_key_path[PATH_MAX];
  char server_pubkey_path[PATH_MAX];
  char client_privkey_path[PATH_MAX];
  char log_file[PATH_MAX];
  LogLevel log_level;
  // Target
  char host[256];
  uint16_t port;

  // Modes
  HmacMode hmac_mode;   // Strongly typed!
  int encrypt;          // 0 = no encryption, 1 = encrypt
  int dead_drop;        // 0 = structured, 1 = dead drop
  int output_mode;      // 0 = unset, else SL_OUTPUT_MODE_*

  //User,  Action and Payload
  uint32_t user_id;   // Resolved numeric user ID after parsing
  uint32_t action_id;
  uint8_t payload[MAX_PAYLOAD_SIZE]; // Binary safe
  size_t payload_len;

  // Misc
  int verbose;
  OptsResponseType response_type;
} Opts;


/**
 * Parse command-line arguments and fill Opts.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @param opts_out Pointer to Opts to populate
 * @return 1 on success, 0 on failure
 */
int parseOpts(int argc, char *argv[], Opts *opts_out);

/**
 * Print command-line usage instructions.
 */
void printHelp(void);
void opts_dump(const Opts * opts);
#endif // PARSE_OPTS_H
