#ifndef SIGLATCH_RANDOM_H
#define SIGLATCH_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file random.h
 * @brief Singleton random number generator for siglatch runtime
 *
 * This module provides basic random number generation for nonces,
 * challenges, and buffer filling. It supports both integer and
 * buffer-based randomness. Access is through a singleton RandomLib struct.
 *
 * To install:
 *   1. Place random.c and random.h in your stdlib directory
 *   2. Include random.h where needed
 *   3. Call `get_random_lib()` once to access the `RandomLib` object
 */

typedef struct {
    // Lifecycle
    void (*init)(void);                          ///< Optional lifecycle setup
    void (*shutdown)(void);                      ///< Optional teardown logic

    // Seeding
    void (*seed_time)(void);                      ///< Seed from time(NULL)
    void (*seed_time_pid_addr)(void);             ///< Seed from time + pid + memory
    void (*set_seed)(unsigned int seed);          ///< Force specific seed
    int  (*is_seeded)(void);                      ///< Check if seeded
    unsigned int (*get_seed)(void);               ///< Return active seed

    // Random values
    uint32_t (*challenge)(void);                  ///< Random 32-bit challenge
    uint32_t (*u32)(void);                        ///< Random 32-bit unsigned int
    void (*bytes)(uint8_t *buf, size_t len);       ///< Fill a buffer with random bytes
  void (*ascii)(uint8_t *buf, size_t len);   ///< Random printable ASCII
  void (*alnum)(uint8_t *buf, size_t len);   ///< Random alphanumeric
} RandomLib;

const RandomLib *get_random_lib(void);

#endif // SIGLATCH_RANDOM_H
