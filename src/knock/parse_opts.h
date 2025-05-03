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

typedef struct {
    char name[128];  // username or action name
    char host[256];  // host string
    uint32_t id;     // user ID or action ID
} AliasEntry;

typedef enum {
  HMAC_MODE_NONE = 0,   ///< No HMAC signing
  HMAC_MODE_NORMAL = 1, ///< Normal HMAC signing
  HMAC_MODE_DUMMY = 2   ///< Dummy HMAC (testing purposes)
} HmacMode;



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

  //User,  Action and Payload
  uint32_t user_id;   // Resolved numeric user ID after parsing
  uint32_t action_id;
  uint8_t payload[MAX_PAYLOAD_SIZE]; // Binary safe
  size_t payload_len;

  // Misc
  int verbose;
} Opts;


int ensure_dir_exists(const char *path);


/**
 * Read an alias map file (user.map or action.map) into memory.
 * 
 * @param path File path to alias map
 * @param out_list Pointer to AliasEntry* array (allocated inside)
 * @param out_count Pointer to size_t count of entries
 * @return 1 on success, 0 on failure
 */
int read_alias_map(const char *path, AliasEntry **out_list, size_t *out_count);

/**
 * Update or insert an alias entry in memory.
 * 
 * @param list Pointer to AliasEntry* array
 * @param count Pointer to size_t count of entries
 * @param name Alias name (user or action)
 * @param host Host associated with alias
 * @param id Numeric ID (user_id or action_id)
 * @return 1 on success, 0 on failure
 */
int update_alias_entry(AliasEntry **list, size_t *count, const char *name, const char *host, uint32_t id);

/**
 * Write an alias map from memory back to disk.
 * 
 * @param path File path to write alias map
 * @param list AliasEntry array
 * @param count Number of entries
 * @return 1 on success, 0 on failure
 */
int write_alias_map(const char *path, AliasEntry *list, size_t count);



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
