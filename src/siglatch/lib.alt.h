
#ifndef SIGLATCH_LIB_H
#define SIGLATCH_LIB_H

#include "../stdlib/log.h"
#include "../stdlib/time.h"

/**
 * @file lib.h
 * @brief Singleton system library registry for siglatch runtime.
 *
 * Provides centralized access to all runtime subsystems such as logging,
 * time, configuration, and future extensions. This acts as a globally
 * accessible service locator.
 */

typedef struct {
    Logger log;     ///< Logging subsystem (file/screen/control)
    TimeLib time;   ///< Timestamping and formatting utilities
} Lib;

extern Lib lib;

void init_lib(void);       // 🚀 Initialize all subsystems
void shutdown_lib(void);   // 🔻 Shutdown in reverse order

#endif // SIGLATCH_LIB_H
