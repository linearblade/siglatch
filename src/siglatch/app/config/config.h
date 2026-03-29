/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_CONFIG_H
#define SIGLATCH_SERVER_APP_CONFIG_H

#include <limits.h>
#include <stdint.h>
#include <openssl/evp.h>
#include "../../../stdlib/parse/ini.h"

#define MAX_USERS 32
#define MAX_ACTIONS 16
#define MAX_SERVERS 5
#define MAX_DEADDROPS 16

#define MAX_ACTION_NAME 32
#define MAX_KEY_DATA 1024
#define MAX_SERVER_NAME     64
#define MAX_DEADDROP_NAME   64
#define MAX_BUILTIN_NAME    64
#define MAX_OBJECT_NAME     64
#define MAX_RUN_AS_NAME     64
//#define MAX_ACTIONS         64
//#define MAX_ACTION_NAME     64
#define MAX_PATH_LEN        256

#define MAX_DEADDROP_NAME   64
#define MAX_PATH_LEN        256
#define MAX_FILTERS         16
#define MAX_FILTER_LEN      32
#define MAX_IP_RANGES       16
#define MAX_IP_RANGE_LEN    64

/**
 * @brief Holds per-request or per-daemon scoped view into global config.
 *
 * Currently a placeholder. May later include server name, deaddrop binding,
 * action filtering, or runtime overrides.
 */
typedef struct {
  char path[PATH_MAX];
} siglatch_config_context;

typedef enum {
  SL_PAYLOAD_OVERFLOW_REJECT = 1,
  SL_PAYLOAD_OVERFLOW_CLAMP = 2,
  SL_PAYLOAD_OVERFLOW_INHERIT = 3
} siglatch_payload_overflow_policy;

typedef enum {
  SL_ACTION_HANDLER_INVALID = 0,
  SL_ACTION_HANDLER_SHELL = 1,
  SL_ACTION_HANDLER_BUILTIN = 2,
  SL_ACTION_HANDLER_STATIC = 3,
  SL_ACTION_HANDLER_DYNAMIC = 4
} siglatch_action_handler;

typedef struct {
  unsigned int id;
  char name[MAX_ACTION_NAME];
  char label[MAX_ACTION_NAME];
  siglatch_action_handler handler;
  char builtin[MAX_BUILTIN_NAME];
  char object[MAX_OBJECT_NAME];
  char object_path[PATH_MAX];
  char run_as[MAX_RUN_AS_NAME];
  char constructor[PATH_MAX];
  char destructor[PATH_MAX];
  int keepalive_interval;
  int enabled;
  int require_ascii;
  int exec_split;
  int enforce_wire_auth;                           ///< App/job-layer only; mux does not consume this
  siglatch_payload_overflow_policy payload_overflow;
  char allowed_ips[MAX_IP_RANGES][MAX_IP_RANGE_LEN];
  int allowed_ip_count;
} siglatch_action;

typedef struct {
  unsigned int id;
  char name[64];
  char key_file[PATH_MAX];
  char hmac_file[PATH_MAX];
  int enabled;
  char actions[MAX_ACTIONS][MAX_ACTION_NAME];
  int action_count;
  char allowed_ips[MAX_IP_RANGES][MAX_IP_RANGE_LEN];
  int allowed_ip_count;

  // Loaded key data
  uint8_t key_data[MAX_KEY_DATA];
  int key_length;
  EVP_PKEY *pubkey;
  uint8_t hmac_key[32];
} siglatch_user;

typedef struct {
  unsigned int id;
  char name[MAX_DEADDROP_NAME];                     ///< [deaddrop:<name>] section label
  char label[MAX_DEADDROP_NAME];                    ///< Optional human-readable display label

  char constructor[MAX_PATH_LEN];                   ///< Path to script or binary
  char run_as[MAX_RUN_AS_NAME];
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
  char name[MAX_SERVER_NAME];                  ///< [server:<name>] machine identifier
  char label[MAX_SERVER_NAME];                 ///< Optional human-readable display label
  char priv_key_path[PATH_MAX];
  int key_owned;
  int enabled;
  int logging;
  char log_file[PATH_MAX];
  char bind_ip[MAX_IP_RANGE_LEN];
  char allowed_ips[MAX_IP_RANGES][MAX_IP_RANGE_LEN];
  int allowed_ip_count;
  int port;                                    ///< UDP port
  int secure;                                  ///< 1 = encrypted, 0 = plaintext
  int enforce_wire_decode;                     ///< Mux-layer policy
  int enforce_wire_auth;                       ///< Mux-layer policy
  int output_mode;                             ///< 0=unset, else SL_OUTPUT_MODE_*
  siglatch_payload_overflow_policy payload_overflow;

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
  char default_server[MAX_SERVER_NAME];        ///< Startup default server name (global fallback source)
  int output_mode;                             ///< 0=unset, else SL_OUTPUT_MODE_*
  siglatch_payload_overflow_policy payload_overflow;
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
} siglatch_config;


typedef struct {
  int (*init)(const siglatch_config_context *ctx);                ///< Prepare internal state, optionally attach a context (else default used)
  void (*shutdown)(void);

  int  (*load)(const char *path);                        ///< Read, consume, materialize, and attach config from file
  int  (*load_detached)(const char *path, siglatch_config **out_config); ///< Read, consume, materialize, and return owned config without attaching it
  int  (*consume)(const IniDocument *document);          ///< Build + own config from parsed INI document
  void (*unload)(void);
  siglatch_config *(*detach)(void);                       ///< Export + relinquish ownership
  void (*attach)(siglatch_config * config);   ///< import + acquire ownership
  void (*destroy)(siglatch_config *config);              ///< Destroy a detached config object
  const siglatch_config *(*get)(void);                    ///< Read-only access

  int (*set_context)(const siglatch_config_context *ctx);
  void (*dump)(void);
  void (*dump_ptr)(const siglatch_config *cfg);

  const siglatch_deaddrop *(*deaddrop_starts_with_buffer)(const uint8_t *payload, size_t payload_len);
  int (*action_available_by_user)(uint32_t user_id, const char *action);
  const siglatch_user *(*user_by_id)(uint32_t id);
  const siglatch_user *(*user_by_id_from)(const siglatch_config *cfg, uint32_t id);
  const siglatch_action *(*action_by_id)(uint32_t id);
  const siglatch_action *(*action_by_id_from)(const siglatch_config *cfg, uint32_t id);
  const siglatch_server *(*server_by_name)(const char *name);
  const siglatch_server *(*server_by_name_from)(const siglatch_config *cfg, const char *name);
  int (*server_set_port)(const char *name, int port);
  int (*server_set_binding)(const char *name, const char *bind_ip, int port);
  int (*server_set_enforce_wire_decode)(const char *name, int enabled);
  int (*server_set_enforce_wire_auth)(const char *name, int enabled);
  const siglatch_deaddrop *(*deaddrop_by_name)(const char *name);
  const siglatch_deaddrop *(*deaddrop_by_name_from)(const siglatch_config *cfg, const char *name);
  const char *(*username_by_id)(uint32_t id);
} ConfigLib;




const ConfigLib *get_app_config_lib(void);

#endif // SIGLATCH_SERVER_APP_CONFIG_H
