/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_BASE64_H
#define SIGLATCH_BASE64_H

#include <stddef.h>

/**
 * Base64-encode a buffer.
 *
 * @param input Raw input buffer
 * @param input_len Length of input buffer
 * @param output Output buffer to receive base64 string (must be large enough)
 * @param output_len Length of output buffer
 * @return Number of bytes written (excluding null terminator), or -1 on error
 */
int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len);

#endif // SIGLATCH_BASE64_H
