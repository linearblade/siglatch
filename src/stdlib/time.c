/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "time.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

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

static uint64_t time_monotonic_now_ms(void) {
#if defined(CLOCK_MONOTONIC)
    struct timespec ts = {0};

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
    }
#endif

    return (uint64_t)SIGLATCH_TIME_NOW() * 1000u;
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
  .unix_ts = time_unix_now,
  .monotonic_ms = time_monotonic_now_ms,
  .human = time_human_now,
  .log = time_log_now,
  .unix_string = time_unix_now_string,
};

const TimeLib *get_lib_time(void) {
    return &time_instance;
}
