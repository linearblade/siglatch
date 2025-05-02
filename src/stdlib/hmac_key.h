#ifndef SIGLATCH_HMAC_KEY_H
#define SIGLATCH_HMAC_KEY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
  void (*init)(void);  // Optional: future key management setup
  void (*shutdown)(void); // Optional: cleanup if needed

  /**
   * normalize
   * Normalize a loaded HMAC key into 32-byte binary buffer.
   *
   * Parameters:
   *   input      - Pointer to raw file data (binary or hex).
   *   input_len  - Length of input data.
   *   output     - Pointer to output buffer (must be at least 32 bytes).
   *
   * Returns:
   *   1 on success,
   *   0 on failure.
   */
  int (*normalize)(const uint8_t *input, size_t input_len, uint8_t *output);

} HMACKey;

// Accessor
const HMACKey *get_hmac_key_lib(void);

#endif // SIGLATCH_HMAC_KEY_H
