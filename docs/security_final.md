
# 🔐 Security Guarantees for **siglatchd**

## 📋 Overview

Siglatchd is engineered with a layered security model designed to withstand hostile network environments, including potential UDP packet floods, malformed traffic, replay attacks, and basic cryptographic tampering attempts.

All critical input surfaces are hardened against crashes, buffer overflows, and unauthorized access.

**Security Goals:**
- Provide hardened packet authentication and verification.
- Defend against replay and resource exhaustion attacks.
- Maintain stability and memory safety even under malicious traffic.
- Securely pass payload data to external user scripts.
- Continue improving by implementing adaptive IP rate limiting based on invalid packet detection. (TODO)
- Add option to discard or restrict payloads to ASCII-only when passing to user scripts. (TODO)

---

## 🛡️ Security Measures Implemented

| Layer | Mitigation |
|------|------------|
| **UDP Listener Safety** | Non-blocking socket setup with enforced packet size limits. Oversized packets are dropped immediately. |
| **HMAC Validation** | Each payload includes a SHA-256 HMAC signature (excluding the signature field itself) to ensure payload integrity before decryption. Invalid signatures are rejected immediately. |
| **RSA Encryption** | After HMAC signing, the entire packet (payload + metadata) is encrypted using RSA-2048 public key encryption. Only packets correctly decrypted with the private key are processed. |
| **Decryption Safety** | Only properly RSA-encrypted packets are accepted. Malformed or oversized packets are rejected without processing. |
| **Structure Validation** | Incoming decrypted packets are versioned and timestamp-validated to prevent stale or out-of-spec data injection. |
| **Replay Attack Protection** | Nonce cache ensures that identical packets cannot be reused to repeat an access or attack. |
| **External Script Handling** | When external scripts are started, payload data is passed as base64-encoded text to avoid direct binary injection risks. (Future option to restrict payloads to ASCII-only under consideration.) |
| **Crash Safety** | All memory access paths are guarded. Invalid inputs or cryptographic failures are logged and skipped without causing daemon instability. |
| **Logging and Auditability** | All major error paths are logged both in human-readable form and with error codes for traceability. |

---

## 👨‍💻 Secure Data Flow (Client to Server to Script)

| Stage | Action | Security Mechanism |
|:-----|:-------|:-------------------|
| **Client** | Constructs payload and signs it with HMAC-SHA256 (excluding signature field) | Ensures payload integrity before transmission |
| **Client** | Encrypts entire signed payload with RSA-2048 public key | Protects payload confidentiality during network transmission |
| **Network** | UDP transport delivers encrypted packet to server | Exposed to network threats, but payload remains encrypted and signed |
| **Server (siglatchd)** | Receives packet, checks size, and drops oversized packets immediately | Prevents resource exhaustion attacks |
| **Server (siglatchd)** | Decrypts packet with private key and verifies HMAC signature | Ensures authenticity and integrity of payload |
| **Server (siglatchd)** | Validates packet structure, timestamp, and nonces | Prevents replay and malformed packet attacks |
| **Server (siglatchd)** | Base64-encodes payload before invoking external script | Prevents direct binary injection risks into scripts |
| **External Script** | Receives base64-encoded payload and decodes securely | Future option to restrict to ASCII-only for added safety (TODO) |

---

## 📂 KnockPacket Structure

```c
typedef struct __attribute__((packed)) {
    uint8_t  version;        // Packet format version
    uint32_t timestamp;      // Time when the packet was created
    uint16_t user_id;        // User ID who sent the packet
    uint8_t  action_id;      // Action requested
    uint32_t challenge;      // Anti-replay random value
    uint8_t  hmac[32];       // HMAC for integrity/authentication (nonce)
    uint16_t payload_len;    // Actual length of the payload
    uint8_t  payload[199];   // Payload buffer
} KnockPacket;
```

This structure is signed via HMAC-SHA256 (excluding the `hmac` field itself) before being encrypted with RSA-2048 for transmission.

---

## ⚔️ Threats Addressed

- UDP flood attempts with invalid packets
- Crash attempts via malformed or partial packets
- Replay of captured valid packets (nonce protection)
- Injection of fake packets without valid encryption or valid HMAC signature
- Resource exhaustion via massive jumbo packets
- Slow draining socket attacks (via non-blocking IO)
- Unsafe execution of user scripts (mitigated by base64 encoding)

---

## 🎺 Known Limitations (By Design)

- Siglatchd does not currently perform IP-based rate limiting; heavy sustained attacks could cause log bloating (future enhancement planned).
- Packet confidentiality relies on the security of RSA key pairs managed outside the daemon.
- Time drift between client and server must be within acceptable limits to prevent timestamp validation failures.
- Base64-encoded payloads still require user scripts to handle decoding securely.

---

## 🏯 Summary

Siglatchd aims to provide hardened security suitable for real-world hostile networks by employing:
- Strict packet size enforcement
- SHA-256 HMAC validation of payloads
- RSA-2048 based encryption authentication
- Replay prevention via nonce caching
- Structured error handling and graceful recovery
- Defensive coding practices throughout all network and cryptographic operations
- Safe handling of payload data when invoking external scripts

While not yet field-tested at production scale, siglatchd is being developed with robust protections against common network-layer attacks and consistent internal memory safety across all code paths.
