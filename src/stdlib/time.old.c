
#include "time.h"
#include <time.h>
#include <string.h>
#include <stdio.h>



static void time_init(void) {
    // No initialization needed yet
}

static void time_shutdown(void) {
    // No shutdown needed yet
}

// Internal wrapper around time(NULL) for future portability
static time_t _time_now(void) {
    return time(NULL);
}

static long time_unix_now(void) {
  return (long)_time_now();
}
static const char *time_unix_now_string(void) {
    static char buffer[20];  // Enough to hold a 64-bit integer as a string

    long now = time_unix_now();
    snprintf(buffer, sizeof(buffer), "%ld", now);

    return buffer;
}

static const char *time_human_now(int cache) {
    static char buffer[32];
    static time_t last = 0;

    time_t now = _time_now();
    if (!cache || last == 0 || now != last) {
        const char *raw = ctime(&now);
        if (!raw) return "unknown time";
        strncpy(buffer, raw, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        buffer[strcspn(buffer, "\n")] = '\0';
        last = now;
    }

    return buffer;
}

static const char *time_log_now(void) {
    static char buf[32];  // Enough for "YYYY-MM-DD HH:MM:SS" + null
    time_t now = _time_now();

    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buf;
}

static const TimeLib time_instance = {
    .init         = time_init,
    .shutdown     = time_shutdown,
    .unix         = time_unix_now,
    .human        = time_human_now,
    .log          = time_log_now,
    .unix_string  = time_unix_now_string,
};

const TimeLib *get_lib_time(void) {
    return &time_instance;
}
