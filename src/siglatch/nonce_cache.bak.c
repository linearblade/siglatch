
#include "nonce_cache.h"
#include <string.h>

typedef struct {
    char nonce[NONCE_STRLEN];
    time_t timestamp;
} NonceEntry;

static NonceEntry nonce_cache[NONCE_MAX];
static int nonce_index = 0;

void nonce_cache_init() {
    memset(nonce_cache, 0, sizeof(nonce_cache));
}

int nonce_seen(const char *nonce, time_t now) {
    for (int i = 0; i < NONCE_MAX; ++i) {
        if (nonce_cache[i].nonce[0] == '\0') continue;
        if ((now - nonce_cache[i].timestamp) > NONCE_TTL) {
            nonce_cache[i].nonce[0] = '\0';  // expire old entry
            continue;
        }
        if (strncmp(nonce_cache[i].nonce, nonce, NONCE_STRLEN) == 0) {
            return 1;  // replay detected
        }
    }
    return 0;
}

void nonce_cache_add(const char *nonce, time_t now) {
    strncpy(nonce_cache[nonce_index].nonce, nonce, NONCE_STRLEN);
    nonce_cache[nonce_index].nonce[NONCE_STRLEN - 1] = '\0';
    nonce_cache[nonce_index].timestamp = now;
    nonce_index = (nonce_index + 1) % NONCE_MAX;
}
