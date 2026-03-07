/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#include "lib.h"
#include "../stdlib/log.h"
#include "../stdlib/time.h"

//  SYSTEM SHUTDOWN ORDER MATTERS 
// ───────────────────────────────────────────────
//  Always shutdown in **reverse order** of init
//  This ensures:
//   - Dependencies are respected
//   - Essential services (like logging) stay alive
//   - You don't kill your ability to debug on exit
// ───────────────────────────────────────────────

Lib lib = {
    .log = {0},
    .time = {0}
};

//  SYSTEM INITIALIZATION ORDER 
// ───────────────────────────────────────────────
//  Always initialize in **logical dependency order**
//  This ensures:
//   - Systems are online before others depend on them
//   - Logging is available before any subsystems start
//   - You avoid undefined behavior or silent failures
// ───────────────────────────────────────────────

void init_lib(void) {
    lib.log = get_logger();
    lib.log.init();

    lib.time = get_lib_time();
    lib.time.init();
}

void shutdown_lib(void) {
    lib.time.shutdown();
    lib.log.shutdown();
}
