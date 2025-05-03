/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_HANDLE_PACKET_H
#define SIGLATCH_HANDLE_PACKET_H

#include <stddef.h>
#include "config.h"
#include "../stdlib/payload.h"  // For KnockPacket definition
#include "../stdlib/openssl.h"
/**
 * Handle a fully parsed and validated knock packet.
 * Routes to the corresponding user action script.
 *
 * @param pkt Pointer to validated KnockPacket
 * @param ip  Source IP address as a string
 * @param is_encrypted 1 if encrypted, 0 if plaintext
 * @return 1 on success, 0 on failure
 */
//int handle_packet(const siglatch_config *cfg, const KnockPacket *pkt, const char *ip_addr, int is_encrypted,int valid_signature);
void handle_structured_payload(
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const char *ip
			       );
int runShell(const char *script_path, int argc, char *argv[],int exec_split) ;
#endif // SIGLATCH_HANDLE_PACKET_H
