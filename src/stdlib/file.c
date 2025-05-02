#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for access(), getcwd(), etc.
#include <errno.h> // Don't forget this at the top of file.c!
//#include <limits.h> // for PATH_MAX
#include "file.h"

/**
 * @file file.c
 * @brief Implementation of file utilities for siglatch
 *
 * This module provides file IO helpers, including tilde expansion,
 * safe reading and writing of binary/text files, and fopen wrappers.
 */

static char filelib_last_error[FILELIB_ERRBUF_SIZE];
static const char *fail_emoji = "❌";

static FileLibContext filelib_ctx = {
    .allow_unicode = false,
    .auto_print_errors = true
};

static void filelib_set_defaults(void){
  // Use defaults if NULL passed
  filelib_ctx.allow_unicode = false;
  filelib_ctx.auto_print_errors = true;
}

/**
 * @brief Update the FileLib runtime context settings.
 *
 * @param ctx Pointer to FileLibContext struct. If NULL, no changes are made.
 */
static void filelib_set_context(const FileLibContext *ctx) {
    if (ctx) {
      filelib_ctx = *ctx; // Shallow copy into static context
    }else {
      filelib_set_defaults();
    }
}

static void filelib_init(const FileLibContext *ctx) {
    filelib_set_context(ctx);
}

static void filelib_shutdown(void) {
    // Optional: placeholder for future shutdown logic
}


static void filelib_error_dump(void) {
    if (!filelib_ctx.auto_print_errors) {
        return;
    }

    if (filelib_ctx.allow_unicode) {
        fprintf(stderr, "%s FileLib Error: %s\n", fail_emoji, filelib_last_error);
    } else {
        fprintf(stderr, "FileLib Error: %s\n", filelib_last_error);
    }
}
static void filelib_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(filelib_last_error, sizeof(filelib_last_error), fmt, args);
    va_end(args);

    filelib_error_dump();
}

/**
 * @brief Retrieve the last recorded error message.
 *
 * @return Pointer to internal last error string (null-terminated).
 */
static const char *filelib_last_error_str(void) {
    return filelib_last_error;
}


static int filelib_expand_tilde(const char *input_path, char *output_path, size_t output_size) {
    if (!input_path || !output_path || output_size == 0) {
        filelib_error("Invalid arguments to expand_tilde()");
        return 0;
    }

    if (input_path[0] == '~') {
        const char *home = getenv("HOME");
        if (!home) {
            filelib_error("HOME environment variable not set");
            return 0;
        }

        size_t home_len = strlen(home);
        size_t rest_len = strlen(input_path + 1);

        if (home_len + rest_len + 1 > output_size) {
            filelib_error("Expanded path would overflow buffer");
            return 0;
        }

        snprintf(output_path, output_size, "%s%s", home, input_path + 1);
    } else {
        size_t input_len = strlen(input_path);
        if (input_len + 1 > output_size) {
            filelib_error("Input path too long for buffer");
            return 0;
        }
        strncpy(output_path, input_path, output_size);
        output_path[output_size - 1] = '\0';
    }

    return 1;
}




static FILE *filelib_open(const char *filepath, const char *mode) {
  
  if (!filepath || !mode) {
        filelib_error("Invalid arguments to open: filepath or mode is NULL");
        return NULL;
    }

    char resolved_path[PATH_MAX];
    if (!filelib_expand_tilde(filepath, resolved_path, sizeof(resolved_path))) {
        filelib_error("Failed to expand path: %s", filepath);
        return NULL;
    }

    FILE *fp = fopen(resolved_path, mode);
    if (!fp) {
        filelib_error("Failed to open file: %s (errno: %d: %s)", 
                      resolved_path, errno, strerror(errno));
        return NULL;
    }

    return fp;
}


/**
 * @brief Read bytes from an open file pointer into a buffer.
 *
 * Best-effort read. If invalid arguments are given, sets last_error().
 *
 * @param fp Open file pointer (must not be NULL)
 * @param buffer Destination buffer
 * @param size Number of bytes to read
 * @return Number of bytes actually read (0 if arguments invalid or read error)
 */
static size_t filelib_read_ptr_bytes(FILE *fp, void *buffer, size_t size) {
    if (!fp) {
        filelib_error("filelib_ptr_read_bytes: NULL file pointer provided");
        return 0;
    }
    if (!buffer) {
        filelib_error("filelib_ptr_read_bytes: NULL buffer pointer provided");
        return 0;
    }
    if (size == 0) {
        filelib_error("filelib_ptr_read_bytes: Requested size to read is 0");
        return 0;
    }

    return fread(buffer, 1, size, fp);
}

/**
 * @brief Open a file and read bytes into a buffer.
 *
 * This function expands tildes, opens the file in binary mode,
 * reads up to the specified number of bytes, and closes the file.
 *
 * @param filepath Path to file
 * @param buffer Destination buffer
 * @param size Number of bytes to read
 * @return Number of bytes actually read (0 on failure)
 */
static size_t filelib_read_fn_bytes(const char *filepath, void *buffer, size_t size) {
  FILE *fp = filelib_open(filepath, "rb");
    if (!fp) {
        return 0;
    }

    size_t read_size = filelib_read_ptr_bytes(fp, buffer, size);
    fclose(fp);

    return read_size;
}

static unsigned char *filelib_read(const char *filepath, size_t *out_size) {
    // TODO: implement binary file reading
    return NULL;
}

static char *filelib_read_text(const char *filepath, size_t *out_size) {
    // TODO: implement text file reading
    return NULL;
}

static int filelib_write(const char *filepath, const unsigned char *data, size_t data_size) {
    // TODO: implement binary file writing
    return 0;
}

static int filelib_write_text(const char *filepath, const char *text) {
    // TODO: implement text file writing
    return 0;
}


static const FileLib file_lib = {
    .init          = filelib_init,
    .shutdown      = filelib_shutdown,
    .set_context   = filelib_set_context,
    .expand_tilde  = filelib_expand_tilde,
    .read          = filelib_read,
    .read_text     = filelib_read_text,
    .read_fn_bytes = filelib_read_fn_bytes,
    .read_ptr_bytes= filelib_read_ptr_bytes,
    .write         = filelib_write,
    .write_text    = filelib_write_text,
    .open          = filelib_open,
    .last_error    = filelib_last_error_str
};

const FileLib *get_lib_file(void) {
    return &file_lib;
}
