#ifndef SIGLATCH_CONFIG_H
#define SIGLATCH_CONFIG_H

#include <limits.h>
#include <stdint.h>

#define MAX_USERS 32
#define MAX_ACTIONS 16
#define MAX_ACTION_NAME 32
#define MAX_KEY_DATA 1024

typedef struct {
    char name[MAX_ACTION_NAME];
    char constructor[PATH_MAX];
    char destructor[PATH_MAX];
    int keepalive_interval;
} siglatch_action;

typedef struct {
    char name[64];
    char key_file[PATH_MAX];
    int enabled;
    char actions[MAX_ACTIONS][MAX_ACTION_NAME];
    int action_count;

    // Loaded key data
    uint8_t key_data[MAX_KEY_DATA];
    int key_length;
} siglatch_user;

typedef struct {
    char priv_key_path[PATH_MAX];
    int port;

    siglatch_user users[MAX_USERS];
    int user_count;

    siglatch_action actions[MAX_ACTIONS];
    int action_count;
} siglatch_config;

siglatch_config *load_config(const char *path);
void free_config(siglatch_config *config);
void dump_config(const siglatch_config *cfg);
int load_user_keys(siglatch_config *cfg);

#endif // SIGLATCH_CONFIG_H
