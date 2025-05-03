/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h> // for access(), F_OK
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include "lib.h"
#include "parse_opts.h"
#include "parse_opts_alias.h"
#include "print_help.h"
#include "../stdlib/parse_argv.h"


enum {
  OPT_ID_NONE = 0, //no op. for passing flags to be picked up in parse handler, not set in opts object
  OPT_ID_HMAC_KEY ,
  OPT_ID_PORT,
  OPT_ID_SERVER_KEY,
  OPT_ID_CLIENT_KEY,
  OPT_ID_NO_HMAC,
  OPT_ID_DUMMY_HMAC,
  OPT_ID_NO_ENCRYPT,
  OPT_ID_DEAD_DROP,
  OPT_ID_VERBOSE,
  OPT_ID_LOG,
  OPT_ID_STDIN,
};

static const OptionSpec option_specs[] = {
  { "--port",        OPT_ID_PORT,        1, OPT_KEYED },
  { "--hmac-key",    OPT_ID_HMAC_KEY,    1, OPT_KEYED },
  { "--server-key",  OPT_ID_SERVER_KEY,  1, OPT_KEYED },
  { "--client-key",  OPT_ID_CLIENT_KEY,  1, OPT_KEYED },
  { "--no-hmac",     OPT_ID_NO_HMAC,     0, OPT_FLAG },
  { "--stdin",       OPT_ID_STDIN,       0, OPT_FLAG },
  { "--opts-dump",   OPT_ID_NONE,        0, OPT_FLAG },
  { "--dummy-hmac",  OPT_ID_DUMMY_HMAC,  0, OPT_FLAG },
  { "--no-encrypt",  OPT_ID_NO_ENCRYPT,  0, OPT_FLAG },
  { "--dead-drop",   OPT_ID_DEAD_DROP,   0, OPT_FLAG },
  { "--verbose",     OPT_ID_VERBOSE,     1, OPT_KEYED },
  { "--log",         OPT_ID_LOG,         1, OPT_KEYED },
  { NULL, 0, 0, OPT_UNKNOWN }
};

int ensure_dir_exists(const char *host);
int parseOpts(int argc, char *argv[], Opts *opts_out);
int apply_parsed_opts(const ParsedArgv *parsed, Opts *out);
int opts_validate(Opts *opts) ;

int read_alias_map(const char *path, AliasEntry **out_list, size_t *out_count);
int update_alias_entry(AliasEntry **list, size_t *count, const char *name, const char *host, uint32_t id);
int write_alias_map(const char *path, AliasEntry *list, size_t count);
uint32_t resolve_user_alias(const char *host, const char *name) ;
uint32_t resolve_action_alias(const char *host, const char *name) ;
int opts_attach_stdin(Opts *opts);
int has_stdin(void);
int opts_read_stdin_explicit(Opts *opts);
int opts_read_stdin_explicit_multiline(Opts *opts);
  
int ensure_dir_exists(const char *host) {
  char path[PATH_MAX] = {0};
  snprintf(path, sizeof(path), "%s/.config/siglatch/%s", getenv("HOME"), host);

  struct stat st = {0};
  if (stat(path, &st) == -1) {
    // Directory doesn't exist — try to create
    if (mkdir(path, 0700) != 0) {
      fprintf(stderr, "❌ Failed to create directory: %s (%s)\n", path, strerror(errno));
      return 0;
    } else {
      printf("📂 Created directory: %s\n", path);
    }
  } else {
    // Directory already exists
    printf("📂 Directory already exists: %s\n", path);
  }
  return 1;
}


int parseOpts(int argc, char *argv[], Opts *opts_out) {
  if (argc < 2) {
    return 0; // Not enough arguments
  }
  // dont for get to add --help
  if (strncmp(argv[1], "--help", 6) == 0)
    return 0;

  if (strncmp(argv[1], "--alias", 7) == 0) {
    // Route to alias handler
    return handle_alias(argc, argv);
  }



    
  // Otherwise: normal packet transmission parsing goes here

  ParsedArgv parsed = {0};
  opts_out->hmac_mode =HMAC_MODE_NORMAL ;
  opts_out->encrypt = 1;
  opts_out->verbose = 3;
  if (!lib.parse_argv.parse(argc, argv, &parsed, option_specs)) {
    return 0;
  }
  
  //parse_argv_dump(&parsed);

    
  // Now loop over parsed.options and parsed.positionals
  // Apply to opts_out fields (mapping by spec name)
  if (!apply_parsed_opts(&parsed, opts_out)) {
    return 0;
  }
  //opts_dump(opts_out);
  if (has_stdin() )
    opts_attach_stdin(opts_out);
  //    opts_dump(opts_out);

  if (!opts_validate(opts_out)) {
    return 0;
  }
  if (lib.parse_argv.has(&parsed, "--opts-dump") ){
    lib.parse_argv.dump(&parsed);
    opts_dump(opts_out);
    exit(0);
  }

  return 1; // Success
}

int has_stdin(void) {
    if (isatty(STDIN_FILENO)) {
        printf("🔧 STDIN is a terminal\n");
	return 0;
    } else {
        printf("📦 STDIN is piped or redirected\n");
	return 1;
    }
}

int opts_attach_stdin(Opts *opts) {
    if (isatty(STDIN_FILENO)) {
        // stdin is a terminal → user did NOT pipe data
        return 0;
    }

    ssize_t n = read(STDIN_FILENO, opts->payload, MAX_PAYLOAD_SIZE);
    if (n > 0) {
        opts->payload_len = (size_t)n;
        return 1;
    }

    fprintf(stderr, "❌ stdin read failed or was empty\n");
    return 0;
}

int opts_read_stdin_explicit(Opts *opts) {
    fprintf(stderr, "📥 Reading payload from stdin (--stdin)...\n");

    ssize_t n = read(STDIN_FILENO, opts->payload, MAX_PAYLOAD_SIZE);
    if (n <= 0) {
        fprintf(stderr, "❌ Failed to read from stdin or input was empty\n");
        return 0;
    }

    opts->payload_len = (size_t)n;

    fprintf(stderr, "✅ Read %zu bytes from stdin\n", opts->payload_len);
    return 1;
}

int opts_read_stdin_explicit_multiline(Opts *opts) {
    fprintf(stderr, "📥 Reading multi-line payload from stdin (end with Ctrl+D):\n");

    char buffer[256];
    size_t total = 0;

    while (fgets(buffer, sizeof(buffer), stdin)) {
        size_t len = strlen(buffer);

        // Check for overflow
        if (total + len >= MAX_PAYLOAD_SIZE) {
            fprintf(stderr, "❌ Payload too large (max %d bytes)\n", MAX_PAYLOAD_SIZE);
            return 0;
        }

        memcpy(opts->payload + total, buffer, len);
        total += len;
    }

    if (total == 0) {
        fprintf(stderr, "❌ No input received from stdin\n");
        return 0;
    }

    opts->payload_len = total;
    fprintf(stderr, "✅ Read %zu bytes from stdin\n", opts->payload_len);
    //opts_dump(opts);
    return 1;
}

int opts_validate(Opts *opts) {
    int valid = 1;

    // Host must be provided
    if (opts->host[0] == '\0') {
        fprintf(stderr, "❌ Host not specified!\n");
        valid = 0;
    }

    // User ID must be nonzero
    if (opts->user_id == 0) {
        fprintf(stderr, "❌ Invalid or missing user ID\n");
        valid = 0;
    }

    // Action ID must be nonzero
    if (opts->action_id == 0) {
        fprintf(stderr, "❌ Invalid or missing action ID\n");
        valid = 0;
    }
    // Derive default key paths if missing
    if (opts->hmac_key_path[0] == '\0') {
      const char *home = getenv("HOME");
      if (home) {
        snprintf(opts->hmac_key_path, PATH_MAX, "%s/.config/siglatch/%s/hmac.key", home, opts->host);
      }
    }

    if (opts->server_pubkey_path[0] == '\0') {
      const char *home = getenv("HOME");
      if (home) {
        snprintf(opts->server_pubkey_path, PATH_MAX, "%s/.config/siglatch/%s/server.pub.pem", home, opts->host);
      }
    }
    
    // Port default
    if (opts->port == 0) {
        opts->port = 50000;
    }

    // Verbose level default
    if (opts->verbose < 0 || opts->verbose > 5) {
        opts->verbose = 3;
    }

    // Encrypt should default ON
    if (opts->encrypt < 0) {
        opts->encrypt = 1;
    }

    // Handle dead-drop specific rules
    if (opts->dead_drop) {
        opts->hmac_mode = HMAC_MODE_NONE;
        //opts->encrypt   = 1; // Dead-drop still encrypts
        if (opts->payload_len == 0) {
            fprintf(stderr, "❌ Dead drop payload is required \n");
	    
            valid = 0;
        }
    } else {
      // Structured knock
      // rely on default value , or override from command line.
      //opts->encrypt = 1; // Structured always encrypts
      // Payload is optional here
    }

    return valid;
}

int apply_parsed_opts(const ParsedArgv *parsed, Opts *out) {
  for (int i = 0; i < parsed->num_options; i++) {
    const ParsedOption *opt = &parsed->options[i];

    switch (opt->spec->id) {
    case OPT_ID_NONE:
      break; //no op for handling non assignable or non actionable opts
    case OPT_ID_PORT:
      out->port = (uint16_t)atoi(opt->args[1]);
      break;
    case OPT_ID_HMAC_KEY:
      strncpy(out->hmac_key_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_SERVER_KEY:
      strncpy(out->server_pubkey_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_CLIENT_KEY:
      strncpy(out->client_privkey_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_NO_HMAC:
      out->hmac_mode = HMAC_MODE_NONE;
      break;

    case OPT_ID_DUMMY_HMAC:
      out->hmac_mode = HMAC_MODE_DUMMY;
      break;

    case OPT_ID_NO_ENCRYPT:
      out->encrypt = 0;
      break;

    case OPT_ID_DEAD_DROP:
      out->dead_drop = 1;
      break;

    case OPT_ID_VERBOSE:
      out->verbose = atoi(opt->args[1]);
      break;

    case OPT_ID_LOG:
      strncpy(out->log_file, opt->args[1], PATH_MAX - 1);
      break;
    case OPT_ID_STDIN:
      opts_read_stdin_explicit_multiline(out);
      break;
    default:
      fprintf(stderr, "⚠️  Unhandled option id %d: %s\n", opt->spec->id, opt->args[0]);
      break;
    }
  }

  // --- Positional args: host, user, action, payload ---
  if (parsed->num_positionals < 3) {
    fprintf(stderr, "❌ Missing required positional arguments: host, user, action\n");
    return 0;
  }

  const char *host_str   = parsed->positionals[0];
  const char *user_str   = parsed->positionals[1];
  const char *action_str = parsed->positionals[2];


  // Copy host
  strncpy(out->host, host_str, sizeof(out->host) - 1);
  //out->port = 50000; // Default port for now (TODO: make configurable)

  // 🧠 User alias resolution
  if (isdigit(user_str[0])) {
    out->user_id = (uint32_t)strtoul(user_str, NULL, 10);
  } else {
    out->user_id = resolve_user_alias(host_str, user_str);
    if (out->user_id == 0) {
      fprintf(stderr, "❌ Unknown user alias: %s\n", user_str);
      return 0;
    }
  }

  // 🧠 Action alias resolution
  if (isdigit(action_str[0])) {
    out->action_id = (uint32_t)strtoul(action_str, NULL, 10);
  } else {
    out->action_id = resolve_action_alias(host_str, action_str);
    if (out->action_id == 0) {
      fprintf(stderr, "❌ Unknown action alias: %s\n", action_str);
      return 0;
    }
  }

  // 🧠 Payload (optional)
  if (out->payload_len <= 0) {
    const char *payload    = (parsed->num_positionals >= 4) ? parsed->positionals[3] : NULL;
    if (payload) {
      size_t len = strlen(payload);
      if (len >= MAX_PAYLOAD_SIZE) len = MAX_PAYLOAD_SIZE - 1;

      memcpy(out->payload, payload, len);
      out->payload_len = len;
    } else {
      out->payload_len = 0;
    }
  }
  return 1;
}

uint32_t resolve_action_alias(const char *host, const char *name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/action.map", getenv("HOME"), host);

    AliasEntry *list = NULL;
    size_t count = 0;

    if (!read_alias_map(path, &list, &count)) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (strcmp(list[i].name, name) == 0) {
            uint32_t id = list[i].id;
            free(list);
            return id;
        }
    }

    free(list);
    return 0;
}

uint32_t resolve_user_alias(const char *host, const char *name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/user.map", getenv("HOME"), host);

    AliasEntry *list = NULL;
    size_t count = 0;

    if (!read_alias_map(path, &list, &count)) {
        return 0; // Couldn't load
    }

    for (size_t i = 0; i < count; i++) {
        if (strcmp(list[i].name, name) == 0) {
            uint32_t id = list[i].id;
            free(list);
            return id;
        }
    }

    free(list);
    return 0; // Not found
}

 int read_alias_map(const char *path, AliasEntry **out_list, size_t *out_count) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "❌ Failed to open alias file for reading: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    AliasEntry *list = NULL;
    size_t count = 0;
    size_t capacity = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *name = strtok(line, ",");
        char *host = strtok(NULL, ",");
        char *id_str = strtok(NULL, ",\n");

        if (!name || !host || !id_str) {
            fprintf(stderr, "⚠️  Skipping invalid alias line: %s\n", line);
            continue;
        }

        if (count >= capacity) {
            size_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
            AliasEntry *new_list = realloc(list, new_capacity * sizeof(AliasEntry));
            if (!new_list) {
                fprintf(stderr, "❌ Memory allocation failed while reading alias file.\n");
                free(list);
                fclose(fp);
                return 0;
            }
            list = new_list;
            capacity = new_capacity;
        }

        AliasEntry *entry = &list[count];
        strncpy(entry->name, name, sizeof(entry->name) - 1);
        entry->name[sizeof(entry->name) - 1] = '\0';
        strncpy(entry->host, host, sizeof(entry->host) - 1);
        entry->host[sizeof(entry->host) - 1] = '\0';
        entry->id = (uint32_t)atoi(id_str);

        count++;
    }

    fclose(fp);

    *out_list = list;
    *out_count = count;

    return 1; // Success
}

 int update_alias_entry(AliasEntry **list, size_t *count, const char *name, const char *host, uint32_t id) {
    if (!list || !count || !name || !host) {
        return 0;
    }

    // Try to find existing entry
    for (size_t i = 0; i < *count; i++) {
        if (strcmp((*list)[i].name, name) == 0) {
            // Found existing entry - update it
            strncpy((*list)[i].host, host, sizeof((*list)[i].host) - 1);
            (*list)[i].host[sizeof((*list)[i].host) - 1] = '\0';
            (*list)[i].id = id;

            printf("🔄 Updated alias: %s -> %s (id=%u)\n", name, host, id);
            return 1;
        }
    }

    // Not found — need to append new entry
    AliasEntry *new_list = realloc(*list, (*count + 1) * sizeof(AliasEntry));
    if (!new_list) {
        fprintf(stderr, "❌ Memory allocation failed in update_alias_entry()\n");
        return 0;
    }

    *list = new_list;
    AliasEntry *new_entry = &(*list)[*count];

    strncpy(new_entry->name, name, sizeof(new_entry->name) - 1);
    new_entry->name[sizeof(new_entry->name) - 1] = '\0';
    strncpy(new_entry->host, host, sizeof(new_entry->host) - 1);
    new_entry->host[sizeof(new_entry->host) - 1] = '\0';
    new_entry->id = id;

    (*count)++;
    printf("🎯 Created new alias: %s -> %s (id=%u)\n", name, host, id);
    return 1;
}

 int write_alias_map(const char *path, AliasEntry *list, size_t count) {
    if (!path || !list) {
        return 0;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "❌ Failed to open alias map for writing: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        fprintf(fp, "%s,%s,%u\n", list[i].name, list[i].host, list[i].id);
    }

    fclose(fp);

    printf("✅ Alias map written successfully: %s (%zu entries)\n", path, count);
    return 1;
}


void opts_dump(const Opts *opts) {
    printf("🔎 Dumping Resolved Opts:\n");

    printf("Paths:\n");
    printf("  HMAC Key Path    : %s\n", opts->hmac_key_path);
    printf("  Server PubKey    : %s\n", opts->server_pubkey_path);
    printf("  Client PrivKey   : %s\n", opts->client_privkey_path);
    printf("  Log File         : %s\n", opts->log_file);

    printf("\nTarget:\n");
    printf("  Host             : %s\n", opts->host);
    printf("  Port             : %u\n", opts->port);

    printf("\nModes:\n");
    printf("  HMAC Mode        : %d\n", opts->hmac_mode);
    printf("  Encrypt Payload  : %s\n", opts->encrypt ? "Yes" : "No");
    printf("  Dead Drop        : %s\n", opts->dead_drop ? "Yes" : "No");

    printf("\nUser and Action:\n");
    printf("  User ID          : %u\n", opts->user_id);
    printf("  Action ID        : %u\n", opts->action_id);

    printf("\nPayload (%zu bytes):\n", opts->payload_len);
    if (opts->payload_len > 0) {
        printf("  ");
        for (size_t i = 0; i < opts->payload_len; i++) {
            printf("%02X ", opts->payload[i]);
        }
        printf("\n");
    } else {
        printf("  (No Payload)\n");
    }

    printf("\nMisc:\n");
    printf("  Verbose Level    : %d\n", opts->verbose);
}

