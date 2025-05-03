/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "random.h"
static int random_seeded = 0;
static unsigned int random_current_seed = 0;  // 🆕 Store the actual used seed
static void random_seed_time_pid_addr(void);
// ── Internal Implementation ─────────────────────────────

static void random_init(void) {
    if (!random_seeded) {
        random_seed_time_pid_addr();  // Default better entropy
    }
}

static void random_shutdown(void) {
    random_seeded = 0;
    random_current_seed = 0;
}

static void random_seed_time(void) {
    unsigned int seed = (unsigned int)time(NULL);
    srand(seed);
    random_current_seed = seed;
    random_seeded = 1;
}

static void random_seed_time_pid_addr(void) {
    unsigned int raw = (unsigned int)(time(NULL) ^ (uintptr_t)&random_seeded ^ getpid());
    unsigned int seed = raw % 0xFFFFFFFF;  // Bound it explicitly (though unnecessary for unsigned int)
    srand(seed);
    random_current_seed = seed;
    random_seeded = 1;
}

static int random_is_seeded(void) {
    return random_seeded;
}

static unsigned int random_get_seed(void) {
    return random_current_seed;
}

static void random_set_seed(unsigned int seed) {
    srand(seed);
    random_current_seed = seed;
    random_seeded = 1;
}
// Placeholder for future (e.g., reading from /dev/urandom)
// static void random_seed_urandom(void) { ... }


static uint32_t random_u32(void) {
    if (!random_seeded) random_init();
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

static uint32_t random_challenge(void) {
    return random_u32();
}

static void random_bytes(uint8_t *buf, size_t len) {
    if (!random_seeded) random_init();

    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(rand() % 256);
    }
}

//
// Fill a buffer with printable ASCII (32..126) and null-terminate
static void random_ascii(uint8_t *buf, size_t len) {
    if (!random_seeded) random_init();
    if (len == 0) return;  // Nothing to do

    size_t usable = len - 1;  // Reserve space for '\0'
    for (size_t i = 0; i < usable; ++i) {
        buf[i] = (uint8_t)((rand() % (126 - 32 + 1)) + 32);  // printable range
    }
    buf[usable] = '\0';  // Null-terminate
}

// Fill a buffer with random alphanumeric (0-9, a-z, A-Z) and null-terminate
static void random_alnum(uint8_t *buf, size_t len) {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    size_t charset_size = sizeof(charset) - 1;  // Exclude null terminator

    if (!random_seeded) random_init();
    if (len == 0) return;  // Nothing to do

    size_t usable = len - 1;  // Reserve space for '\0'
    for (size_t i = 0; i < usable; ++i) {
        buf[i] = (uint8_t)charset[rand() % charset_size];
    }
    buf[usable] = '\0';  // Null-terminate
}
// ── Singleton Interface ─────────────────────────────

static const RandomLib random_instance = {
    .init              = random_init,
    .shutdown          = random_shutdown,
    .seed_time         = random_seed_time,
    .seed_time_pid_addr= random_seed_time_pid_addr,
    .set_seed          = random_set_seed,
    .is_seeded         = random_is_seeded,
    .get_seed          = random_get_seed,
    .challenge         = random_challenge,
    .u32               = random_u32,
    .bytes             = random_bytes,
    .ascii             = random_ascii,
    .alnum             = random_alnum,
};
const RandomLib *get_random_lib(void) {
    return &random_instance;
}
