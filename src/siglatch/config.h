/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_CONFIG_H
#define SIGLATCH_CONFIG_H

#include <limits.h>
#include <stdint.h>
#include <openssl/evp.h>

#define MAX_USERS 32
#define MAX_ACTIONS 16
#define MAX_SERVERS 5
#define MAX_DEADDROPS 16

#define MAX_ACTION_NAME 32
#define MAX_KEY_DATA 1024
#define MAX_SERVER_NAME     64
#define MAX_DEADDROP_NAME   64
//#define MAX_ACTIONS         64
//#define MAX_ACTION_NAME     64
#define MAX_PATH_LEN        256

#define MAX_DEADDROP_NAME   64
#define MAX_PATH_LEN        256
#define MAX_FILTERS         16
#define MAX_FILTER_LEN      32

/**
 * @brief Holds per-request or per-daemon scoped view into global config.
 *
 * Currently a placeholder. May later include server name, deaddrop binding,
 * action filtering, or runtime overrides.
 */
typedef struct {
  char path[PATH_MAX];
} siglatch_config_context;

typedef struct {
  unsigned int id;
  char name[MAX_ACTION_NAME];
  char constructor[PATH_MAX];
  char destructor[PATH_MAX];
  int keepalive_interval;
  int enabled;
  int require_ascii;
  int exec_split;
} siglatch_action;

typedef struct {
  unsigned int id;
  char name[64];
  char key_file[PATH_MAX];
  char hmac_file[PATH_MAX];
  int enabled;
  char actions[MAX_ACTIONS][MAX_ACTION_NAME];
  int action_count;

  // Loaded key data
  uint8_t key_data[MAX_KEY_DATA];
  int key_length;
  EVP_PKEY *pubkey;
  uint8_t hmac_key[32];
} siglatch_user;

typedef struct {
  unsigned int id;
  char name[MAX_DEADDROP_NAME];                     ///< [deaddrop:<name>] section label

  char constructor[MAX_PATH_LEN];                   ///< Path to script or binary
  char filters[MAX_FILTERS][MAX_FILTER_LEN];        ///< List of prefix filters (optional)
  int filter_count;

  char starts_with[MAX_FILTERS][MAX_FILTER_LEN];
  int starts_with_count;
  int enabled;
  int require_ascii;
  int exec_split;
  // Optional future:
  // int log_output;
  // int timeout_ms;
  // int pass_env;
} siglatch_deaddrop;

typedef struct {
  unsigned int id;
  char name[MAX_SERVER_NAME];                  ///< [server:<name>] section label
  char priv_key_path[PATH_MAX];
  int key_owned;
  int enabled;
  int logging;
  char log_file[PATH_MAX];
  int port;                                    ///< UDP port
  int secure;                                  ///< 1 = encrypted, 0 = plaintext

  EVP_PKEY *priv_key;                          ///< Loaded OpenSSL private key

  char deaddrops[MAX_ACTIONS][MAX_ACTION_NAME];
  int deaddrop_count;
  char actions[MAX_ACTIONS][MAX_ACTION_NAME];  ///< List of allowed actions
  int action_count;
} siglatch_server;

typedef struct {
  // Global log path (used if no per-server override)
  char log_file[PATH_MAX];
  char priv_key_path[PATH_MAX];
  EVP_PKEY *master_privkey;                          ///< Loaded OpenSSL private key
  // Users and their keys
  siglatch_user users[MAX_USERS];
  int user_count;

  // Available actions (globally defined, servers link by name)
  siglatch_action actions[MAX_ACTIONS];
  int action_count;

  // Server blocks (forked individually)
  siglatch_server servers[MAX_SERVERS];
  int server_count;

  // Deaddrop definitions (linked by name from server)
  siglatch_deaddrop deaddrops[MAX_DEADDROPS];
  int deaddrop_count;
  siglatch_server * current_server;
} siglatch_config;


/*
siglatch_config *load_config(const char *path);

void free_config(siglatch_config *config);
void dump_config(const siglatch_config *cfg);
*/
/*
int load_server_keys(siglatch_config *cfg);
int load_user_keys(siglatch_config *cfg);
int load_user_hmac_keys(siglatch_config *cfg);
int load_master_key(siglatch_config *cfg);
*/

typedef struct {
  int (*init)(const siglatch_config_context *ctx);                ///< Prepare internal state, optionally attach a context (else default used)
  void (*shutdown)(void);

  int  (*load)(const char *path);                         ///< Load + own config
  void (*unload)(void);
  siglatch_config *(*detach)(void);                       ///< Export + relinquish ownership
  void (*attach)(siglatch_config * config);   ///< import + acquire ownership
  const siglatch_config *(*get)(void);                    ///< Read-only access

  int (*set_context)(const siglatch_config_context *ctx);
  void (*dump)(void);
  void (*dump_ptr)(const siglatch_config *cfg);

  const siglatch_deaddrop *(*deaddrop_starts_with_buffer)(const uint8_t *payload, size_t payload_len);
  int (*current_server_deaddrop_available)(const char *deaddrop_name);
  int (*current_server_action_available)(const char *action_name);
  const siglatch_deaddrop *(*current_server_deaddrop_starts_with_buffer) (const uint8_t *payload, size_t payload_len, char *match, int match_buf_size, size_t *matched_prefix_len);
  const siglatch_server *  (*set_current_server)(const char * name);
  const siglatch_server*  (*get_current_server)(void);
  const siglatch_user *(*user_by_id)(uint32_t id);
  const siglatch_action *(*action_by_id)(uint32_t id);
  const siglatch_server *(*server_by_name)(const char *name);
  const siglatch_deaddrop *(*deaddrop_by_name)(const char *name);
  const char *(*username_by_id)(uint32_t id);
} ConfigLib;




const ConfigLib *get_lib_config(void);

#endif // SIGLATCH_CONFIG_H
