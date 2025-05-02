
# 🔐 `siglatch`: Secure UDP Signal-Triggered Access Daemon

## 📦 Project Overview

**Siglatch** is a secure, encrypted, stealthy command receiver and access controller for remote infrastructure. Inspired by port knocking and dead drop mechanics, it enables temporary access to a private network by receiving authenticated UDP packets. It is designed to operate in hostile network environments where IPs change frequently and visibility must be minimized.

## 🌐 Architecture

```
[Client with Dynamic IP]         [Remote Colo Network]
+-----------------------+        +-----------------------------+
| knock/main.c         |  UDP   | siglatch/main.c (daemon)    |
| Sends knock packets  +------->+ Listens on UDP port         |
| w/ HMAC + timestamp  |        | Tracks IP knock state       |
| Optional keepalives  |        | Auto-expires inactive IPs   |
+-----------------------+        +-----------------------------+
```

## ✅ Features (Implemented and Planned)

### 🔹 `knock/main.c` — UDP Knock Sender

Sends an encrypted UDP request. This uses both a master key and a client key, for the purpose of masking network traffic. This enables secure remote functionality.

### 🔹 `siglatch/main.c` — Knock Daemon

Receives user traffic, decrypts, and takes action.

- Invalid traffic can trigger a rate limiter or enable packet dropping to mediate potential DDoS activity.
- Commands can be set to require a keepalive or trigger a timeout handler (e.g., run a destructor).

### 🔹 Scripts

- Scriptable hooks for: IP allow, IP revoke, or any system-level actions within the client’s allowed permissions.
- Script hooks are configured per user action permission. Example: a user's key may allow running a "grant IP", "revoke IP", or "start specific job" script.

### 📈 Features (Planned)

- Script timeouts: after a script has been executed, a timer will begin. If a keepalive is not sent within the timeout window, a destructor script will automatically be called.
  - Example: grant IP -> timeout without keepalive -> automatically revoke IP.
- Full "dead drop" functionality:
  - Normal workflow will be implemented using the structured packet format outlined in the security document.
  - A "dead drop mode" will also be available for both encrypted and unencrypted traffic.
  - In dead drop mode, normal packet structuring is bypassed. External scripts will be responsible for handling signature validation and data processing.
  - Both modes are configurable.
  - **Advantages:** extra usable space in packets, DIY flexibility, creative dead drop mechanics.
  - **Disadvantages:** no built-in security unless explicitly handled by the user.
- Server-to-client communication:
  - Currently, both client and server maintain encrypted keys for authentication, but only the client can send.
  - Future functionality will enable the server to send encrypted responses back to clients.
  - This will allow **menu-driven services** where a client can query and receive structured, authenticated replies.

## 🧑‍💼 Access Control & User-Specific Commands

Siglatch supports scoped command execution based on the authenticated user's key. Each client key (or key ID) can be associated with a predefined menu of allowed operations, enabling flexible yet secure delegation of actions.

- The daemon will maintain a per-key **access control list (ACL)** mapping key IDs to permitted commands.
- Clients may request any command from their permitted list, or a fallback/default action if none is specified.
- Unauthorized or unlisted commands will be rejected and optionally logged or rate-limited.

## 🛡️ Cryptographic Handling (Stub)

- Authentication via HMAC with dual-key model: master and per-client keys.
- All messages are timestamped to prevent replay.
- Signature validation is strict, with optional clock skew tolerance.
- Keys may be rotated or revoked via simple config changes or reload.

## ⚠️ Failure Modes & Error Behavior (Stub)

- Malformed or invalid packets: log and drop.
- Timeout on keepalive: revoke access, optionally trigger destructor.
- Clock drift: configurable tolerance window.
- Rate-limiting for repeated bad traffic (potential DDoS mitigation).

## ⚙️ Configuration & Extensibility

- Configurable actions may be defined and associated with user permissions.
- Users can be added with access to a subset of allowed actions.
- Timeout durations and keepalive behavior are adjustable.
- Script paths and allowed commands are configurable.
- Installation and management scripts are provided in the base directory for ease of setup and configuration.

## ⚠️ Operational Considerations

- May be able to run without root privileges if scripted actions fall within the non-privileged user's scope.
- Scripts execute with the privileges of the daemon's runtime user.
- Scripting should be limited to safe, trusted operations to avoid privilege escalation risks.

## 🗓️ Next Steps (Working Plan)

1. ✅ Add keepalive support and session expiry logic
2. 🧪 Test auto-revoke logic after timeout
3. 📦 Develop small suite of scripts for operational use:
   - Add/revoke IP for SSH access
   - Run system or audit reports
   - Enable/disable administrative panels and services
4. 🔹 Improve client usability:
   - Expand client functionality to match server capabilities
   - Implement menu-driven actions and better user interaction workflows
   - Focus on usability, flexible input options, and dynamic command handling
