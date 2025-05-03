/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


//🧠 “No more logs today.” — Sun Tzu, probably

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>     // for errno
#include <string.h>    // for strerror()
//#include "../siglatch/lib.h"

#include "log.h"
#include "log_context.h"
#include "utils.h"  // for timestamp_now()





/**
 * @file log.c
 * @brief Singleton-style logger module for siglatchd
 *
 * This file provides a centralized, singleton-like logging interface
 * for use across the `siglatchd` project. It encapsulates internal state
 * using static variables to simulate an object-like logger instance.
 *
 * Features:
 *   - Timestamped log output
 *   - Multiple log levels (INFO, DEBUG)
 *   - Enable/disable logging globally
 *   - Format string support (like printf)
 *
 * Usage:
 *   log_set_enabled(1);           // Enable logging
 *   log_set_level(2);             // Set log level (e.g., DEBUG)
 *   log_info("Listening on port %d\n", port);
 *   log_debug("Raw packet: %s\n", hex);
 *
 * Internal state is not exposed — consumers interact via log.h only.
 */

static void log_close_file(void);




// ── static state ─────────────────────────────
static FILE *log_output = NULL;         // Current log output stream
static int log_output_owned = 0;        // We opened it — must close
static int logging_enabled = 1;         // Master toggle for logging
static int debug_to_stdout = 1;         // Should debug() output to terminal?
static int error_to_stderr = 1;         // errors to std_err
static int current_level = 1;           // Log verbosity: 0=off, 1=info, 2=debug
static LogContext log_ctx = {0}; 
// -- internal impls --

static const char *default_time() {
    return "1970-01-01 00:00:00";  // fallback in case of no time context
}

static const char *(*get_time_func)(void) = default_time;  // ← global time provider
//static const TimeLib *time_provider = NULL;

// -- constructor 
static void log_init(LogContext ctx) {
    log_output = NULL;
    log_output_owned = 0;
    logging_enabled = 1;
    debug_to_stdout = 1;
    current_level = 1;
    log_ctx = ctx; 
    get_time_func = (ctx.time && ctx.time->log) ? ctx.time->log : default_time;
    
    /*
static const TimeLib *get_default_time() {
    static TimeLib fallback = {
        .log = default_time_log
    };
    return &fallback;
}

static const char *default_time_log() {
    return "1970-01-01 00:00:00";
}
    */
    /*
      const char *ts = (time_provider && time_provider->log)
               ? time_provider->log()
               : "???";
     */
}
// -- destructor
static void log_shutdown(void) {
    if (log_output_owned && log_output) {
        fprintf(log_output, "🔻 Logger shutting down\n");
     }
    log_close_file();
}



// start -- log file management
static int log_open_file(const char *path) {
  if (!path || path[0] == '\0') {
    return 0;  // Treat empty path as "no logging"
  }
  FILE *fp = fopen(path, "a");
  if (!fp) return 0;

  if (log_output_owned && log_output) {
    fclose(log_output);  // Close any previously owned log
  }

  log_output = fp;
  log_output_owned = 1;
  return 1;  // Success
}

static void log_close_file(void) {
    if (log_output_owned && log_output) {
        fclose(log_output);
    }

    log_output = NULL;
    log_output_owned = 0;
}
 
static void log_set_handle(FILE *fp)       { log_output = fp; }
// end -- log file management

// start -- private

static void log_console_line(const char *line) {
    if (!debug_to_stdout )
        return;

    fputs(line, stdout);
}

static void log_console_error(const char *line) {
  if (!error_to_stderr ){
    log_console_line(line);
  }else {
    fputs(line, stderr);
  }
}


static void log_write_line(const char *line) {
  if (!logging_enabled || !log_output )
    return;
    fputs(line, log_output);
}

static const char *log_level_name(LogLevel level) {
  switch (level) {
  case LOG_NONE: return "NONE";
  case LOG_ERROR: return "ERROR";
  case LOG_WARN:  return "WARN";
  case LOG_INFO:  return "INFO";
  case LOG_DEBUG: return "DEBUG";
  case LOG_TRACE: return "TRACE";
  default:        return "LOG";
  }
}

static void format_line(char *buffer, size_t bufsize, const char *fmt, va_list args) {
    int written = vsnprintf(buffer, bufsize, fmt, args);
    buffer[bufsize - 1] = '\0';  // Defensive

    if (written >= (int)bufsize && bufsize >= 4) {
        strcpy(buffer + bufsize - 4, "...");
    }
}

//end -- private

static void log_set_enabled(int enable)  { logging_enabled = enable; }
static void log_set_debug(int enable)    { debug_to_stdout = enable; }
static void log_set_level(int level)     { current_level = level; }



static void log_console(const char *fmt, ...) {
    char buffer[1024];  // Adjust size as needed
    va_list args;

    va_start(args, fmt);
    format_line(buffer,sizeof(buffer), fmt,args);
    va_end(args);

    log_console_line(buffer); 
}


static const char *build_log_prefix(LogLevel level) {
    static char ts[64];  // Thread-unsafe (but fine for single-thread)
    const char *tag = log_level_name(level);
    snprintf(ts, sizeof(ts), "[%s] [%s] ", get_time_func(),tag);
    return ts;
}

/*/
    //uncomment if needed, otherwise gcc bitches
static void log_write_timestamp(LogLevel level) {
    log_write_line(build_log_prefix(level));
}
*/


static void log_write(const char *fmt, ...) {

  char buffer[1024];  // Formatted log line
  va_list args;
  va_start(args, fmt);
  format_line(buffer,sizeof(buffer), fmt,args);
  va_end(args);
  log_write_line(buffer);
}

static void log_console_write(const char *fmt, ...) {
    char buffer[1024];  // Formatted message
    va_list args;
    
    va_start(args, fmt);
    format_line(buffer,sizeof(buffer), fmt,args);
    va_end(args);

    log_write_line(buffer);     // Send to log file
    log_console_line(buffer);   // Send to screen
}

static void log_emit(LogLevel level, int to_console, const char *fmt, ...) {

  if (level > current_level){
    return;  // 🔒 Level filtering here
  }
    const char * prefix = build_log_prefix(level);

    char message[1024];
    va_list args;
    va_start(args, fmt);
    format_line(message, sizeof(message), fmt, args);
    va_end(args);


    if (logging_enabled && log_output){  // ✅ File
      log_write_line(prefix);
      log_write_line(message);    
    }
    
    if (to_console && debug_to_stdout){ // ✅ Terminal
      if (level == LOG_ERROR){
	log_console_error(prefix);
	log_console_error(message);
      }else {
	log_console_line(prefix);
	log_console_line(message);   
      }

    }
}


static void log_perror(const char *prefix) {
    const char *err = strerror(errno);
    log_emit(LOG_ERROR, 1, "%s: %s\n", prefix, err);
}



// -- singleton --
static const Logger logger = {
    .init           = log_init,
    .shutdown       = log_shutdown,

    .set_handle     = log_set_handle,
    .open           = log_open_file,
    .close          = log_close_file,
    .set_enabled    = log_set_enabled,
    .set_debug      = log_set_debug,
    .set_level      = log_set_level,
    .console        = log_console,
    .write          = log_write,
    .console_write  = log_console_write,
    .emit           = log_emit,
    .perror         = log_perror
};

/*
Logger get_logger(void){
  return logger;
}
*/

const Logger *get_logger(void) {
    return &logger;
}


//printf("[%s] 📩 %zd bytes from %s\n", timestr, n, ip);
/*
void log_with_time(const char *fmt, ...) {
  //log_with_time("📩 %zd bytes from %s\n", n, ip);
    time_t now = time(NULL);
    char *timestr = ctime(&now);
    timestr[strcspn(timestr, "\n")] = 0;

    va_list args;
    va_start(args, fmt);
    printf("[%s] ", timestr);
    vprintf(fmt, args);
    va_end(args);
}
*/
