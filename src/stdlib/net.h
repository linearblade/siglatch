/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NET_SHIM_H
#define SIGLATCH_NET_SHIM_H

/*
 * Compatibility shim for the promoted stdlib net subtree.
 *
 * The active implementation now lives under `stdlib/net/`.
 * Keep this top-level include so existing callers can migrate without
 * touching every include site at once.
 */
#include "net/net.h"

#endif /* SIGLATCH_NET_SHIM_H */
