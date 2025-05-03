/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "hmac_key.h"
#include <string.h>
#include <ctype.h>   // for isxdigit()
#include <stdio.h>   // for sscanf()

// Internal implementation

void hmac_key_init(void) {
    // Placeholder: no initialization needed yet
}

void hmac_key_shutdown(void) {
    // Placeholder: no shutdown needed
}
//
#include <ctype.h>
#include <string.h>
#include <stdio.h>


//
#include <ctype.h>
#include <string.h>
#include <stdio.h>

int hmac_key_normalize(const uint8_t *input, size_t input_len, uint8_t *output) {
    if (!input || !output) {
        return 0;
    }

    // 1. If raw binary (32 bytes), skip grooming
    if (input_len == 32) {
        memcpy(output, input, 32);

        // Extra sanity check: not all zero
        int all_zero = 1;
        for (int i = 0; i < 32; ++i) {
            if (output[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            return 0;
        }

        return 1;
    }

    // 2. Otherwise, groom hex-encoded input
    uint8_t groomed_buf[128] = {0};  // Big enough
    size_t groomed_len = 0;

    for (size_t i = 0; i < input_len; ++i) {
        if (input[i] == ' ' || input[i] == '\n' || input[i] == '\r' || input[i] == '\t') {
            continue;  // Skip whitespace
        }
        groomed_buf[groomed_len++] = input[i];
    }

    if (groomed_len != 64) {
        return 0;  // Not valid hex string length
    }

    // 3. Parse hex-encoded key
    for (size_t i = 0; i < 32; ++i) {
        char hex_byte[3] = {0};
        hex_byte[0] = groomed_buf[i * 2];
        hex_byte[1] = groomed_buf[i * 2 + 1];

        if (!isxdigit(hex_byte[0]) || !isxdigit(hex_byte[1])) {
            return 0;
        }

        unsigned int byte_value = 0;
        if (sscanf(hex_byte, "%02x", &byte_value) != 1) {
            return 0;
        }
        output[i] = (uint8_t)byte_value;
    }

    // Final sanity check: not all zero
    int all_zero = 1;
    for (int i = 0; i < 32; ++i) {
        if (output[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        return 0;
    }

    return 1;
}
// Singleton accessor

static const HMACKey hmac_key = {
    .init = hmac_key_init,
    .shutdown = hmac_key_shutdown,
    .normalize = hmac_key_normalize,
};

const HMACKey *get_hmac_key_lib(void) {
    return &hmac_key;
}
