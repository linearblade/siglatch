/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"
#include "lib.h"
// Trim leading and trailing whitespace
char *trim(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str; // all spaces

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;
    return str;
}

siglatch_config *load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOGPERR("fopen");
        return NULL;
    }

    siglatch_config *config = calloc(1, sizeof(siglatch_config));
    if (!config) {
        fclose(fp);
        return NULL;
    }

    // Set defaults
    strncpy(config->priv_key_path, "/etc/siglatch/server_priv.pem", PATH_MAX);
    config->port = 50000;

    char line[512];
    siglatch_user *current_user = NULL;
    siglatch_action *current_action = NULL;

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);
        if (trimmed[0] == '#' || trimmed[0] == ' ') continue;

        if (strncmp(trimmed, "[user:", 6) == 0) {
            if (config->user_count >= MAX_USERS) continue;
            current_action = NULL;
            current_user = &config->users[config->user_count++];
            sscanf(trimmed, "[user:%63[^]]", current_user->name);
            continue;
        }

        if (strncmp(trimmed, "[action:", 8) == 0) {
            if (config->action_count >= MAX_ACTIONS) continue;
            current_user = NULL;
            current_action = &config->actions[config->action_count++];
            sscanf(trimmed, "[action:%31[^]]", current_action->name);
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = ' ';
        char *key = trim(trimmed);
        char *val = trim(eq + 1);

        if (!current_user && !current_action) {
            if (strcmp(key, "priv_key_path") == 0) {
                strncpy(config->priv_key_path, val, PATH_MAX);
            } else if (strcmp(key, "port") == 0) {
                config->port = atoi(val);
            }
        } else if (current_action) {
            if (strcmp(key, "constructor") == 0) {
                strncpy(current_action->constructor, val, PATH_MAX);
            } else if (strcmp(key, "destructor") == 0) {
                strncpy(current_action->destructor, val, PATH_MAX);
            } else if (strcmp(key, "keepalive_interval") == 0) {
                current_action->keepalive_interval = atoi(val);
            }
        } else if (current_user) {
            if (strcmp(key, "enabled") == 0) {
                current_user->enabled = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
            } else if (strcmp(key, "key_file") == 0) {
                strncpy(current_user->key_file, val, PATH_MAX);
            } else if (strcmp(key, "actions") == 0) {
                char *tok = strtok(val, ",");
                while (tok && current_user->action_count < MAX_ACTIONS) {
                    strncpy(current_user->actions[current_user->action_count++],
                            trim(tok), MAX_ACTION_NAME);
                    tok = strtok(NULL, ",");
                }
            }
        }
    }

    fclose(fp);
    return config;
}
