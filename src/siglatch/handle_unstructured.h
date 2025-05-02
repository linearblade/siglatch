#ifndef SIGLATCH_HANDLE_UNSTRUCTURED_H
#define SIGLATCH_HANDLE_UNSTRUCTURED_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file handle_unstructured.h
 * @brief Handles raw or unstructured UDP payloads (e.g., dead-drops, malformed knocks)
 *
 * This interface is used when deserialization fails or when packets are deliberately
 * structureless (e.g., testing or anonymous messages). It logs or inspects the
 * content and may later support routing to dead-drop hooks.
 */

/**
 * @brief Processes an unstructured payload after decryption fallback.
 *
 * This function handles encrypted or plaintext payloads that failed deserialization
 * into a KnockPacket. Typically used for debugging, diagnostics, or future
 * dead-drop-style transmission support.
 *
 * @param payload      Pointer to raw (unencrypted or decrypted) data
 * @param payload_len  Length of the payload in bytes
 * @param ip           Client IP address (may be logged)
 */
void handle_unstructured_payload( const uint8_t *payload, size_t payload_len, const char *ip);
#endif // SIGLATCH_HANDLE_UNSTRUCTURED_H
