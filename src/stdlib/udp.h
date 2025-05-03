/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_UDP_H
#define LIB_UDP_H

#include <stddef.h>
#include <stdint.h>
#include "log.h" // for Logger

/**
 * UdpContext – runtime context for UDP operations.
 */
typedef struct {
    const Logger *log;  ///< Pointer to logging interface (must not be NULL)
    // Future: persistent socket, timeout config, etc.
} UdpContext;

/**
 * UdpLib – basic UDP send interface with optional lifecycle and context.
 */
typedef struct {
    /**
     * Initialize the UDP library with optional context.
     */
    void (*init)(const UdpContext *ctx);

    /**
     * Override context after init (for runtime reconfiguration).
     */
    void (*set_context)(const UdpContext *ctx);

    /**
     * Optional shutdown hook.
     */
    void (*shutdown)(void);

    /**
     * Send a UDP payload to a given target:port.
     *
     * @param target_ip    String IPv4 address (e.g., "127.0.0.1")
     * @param port         Destination port (host byte order)
     * @param data         Pointer to payload buffer
     * @param data_len     Length of payload buffer
     * @return 1 on success, 0 on failure
     */
    int (*send)(const char *target_ip, uint16_t port,
                const unsigned char *data, size_t data_len);

} UdpLib;

/**
 * Get the singleton UDP library instance.
 */
const UdpLib *get_udp_lib(void);

#endif // LIB_UDP_H
