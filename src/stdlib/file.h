#ifndef SIGLATCH_FILE_H
#define SIGLATCH_FILE_H

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h> // for bool
#include <limits.h> // for PATH_MAX
#include <stdarg.h> //va args
// ---- Public Constants ----

/**
 * @brief Maximum size of error message buffer (excluding null terminator).
 */
#define FILELIB_ERRBUF_SIZE 256

/**
 * @brief Safe fallback definition for PATH_MAX if not provided by the system.
 */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * @file file.h
 * @brief Singleton file utilities library for reading, writing, and path expansion
 *
 * This module provides unified file handling for the siglatch runtime.
 * It supports safe binary and text file IO, tilde path expansion,
 * and standardized memory management for file operations.
 *
 * Access is provided through a singleton FileLib structure.
 *
 * To install:
 *   1. Place file.c and file.h in your stdlib directory
 *   2. Include file.h where needed
 *   3. Call `get_lib_file()` once to access the `FileLib` object
 */

typedef struct {
    bool allow_unicode; ///< Whether Unicode output (emoji) is enabled
    bool auto_print_errors; ///< Whether to automatically fprintf errors when they happen
} FileLibContext;

typedef struct {
  void (*init)(const FileLibContext * ctx); ///< Optional lifecycle setup (reserved for future use)
  void (*shutdown)(void); ///< Optional teardown logic (reserved)
  void (*set_context)(const FileLibContext * ctx);
  int (*expand_tilde)(const char *input_path, char *output_path, size_t output_size);

  unsigned char *(*read)(const char *filepath, size_t *out_size);
  char *(*read_text)(const char *filepath, size_t *out_size);
  size_t (*read_fn_bytes)(const char *filepath, void *buffer, size_t size);
  size_t (*read_ptr_bytes)(FILE *fp, void *buffer, size_t size);
  
  int (*write)(const char *filepath, const unsigned char *data, size_t data_size);
  int (*write_text)(const char *filepath, const char *text);

  FILE *(*open)(const char *filepath, const char *mode);
  const char *(*last_error)(void);
} FileLib;

/**
 * Access the singleton FileLib instance.
 *
 * @return Pointer to the FileLib structure.
 */
const FileLib *get_lib_file(void);

#endif // SIGLATCH_FILE_H
