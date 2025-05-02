#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// Placeholder: real parsing logic goes here
siglatch_config *load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
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

    // TODO: real parsing logic here

    fclose(fp);
    return config;
}

void free_config(siglatch_config *config) {
    if (config) {
        free(config);
    }
}
