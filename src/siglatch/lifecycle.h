/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_LIFECYCLE_H
#define SIGLATCH_LIFECYCLE_H

int siglatch_boot(void);
void siglatch_shutdown(void);
void siglatch_report_config_error(void);
void siglatch_report_shutdown_complete(void);

#endif
