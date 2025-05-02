#include "time.h"
#include <time.h>
#include <string.h>
#include <stdio.h>

#ifndef SIGLATCH_TIME_NOW
#define SIGLATCH_TIME_NOW _time_now
#endif

// Internal system time abstraction for portability/mock override
static time_t _time_now(void) {
    return time(NULL);
}

static void time_init(void) {
    // No initialization needed for now
}

static void time_shutdown(void) {
    // No cleanup required
}

static long time_unix_now(void) {
    return (long)SIGLATCH_TIME_NOW();
}

static const char *time_unix_now_string(void) {
    static char buffer[20];
    time_t now = SIGLATCH_TIME_NOW();
    snprintf(buffer, sizeof(buffer), "%ld", (long)now);
    return buffer;
}

static const char *time_human_now(int cache) {
    static char buffer[32];
    static time_t last = 0;
    time_t now = SIGLATCH_TIME_NOW();

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
    static char buf[32];
    time_t now = SIGLATCH_TIME_NOW();
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buf;
}

static const TimeLib time_instance = {

  .init = time_init,
  .shutdown = time_shutdown,
  .now = _time_now,
  .unix = time_unix_now,
  .human = time_human_now,
  .log = time_log_now,
  .unix_string = time_unix_now_string,
};

const TimeLib *get_lib_time(void) {
    return &time_instance;
}
