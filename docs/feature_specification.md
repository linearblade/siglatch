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

## 🧠 Knock Sequence Design

Client sends X knocks in correct order (e.g., `step1`, `step2`, `step3`), separated by Y seconds each.

On success, server runs `knock_grant.sh <IP>`.

Server monitors last knock timestamp.

If no keepalive knock is received within a timeout (e.g., 5 min), server runs `knock_revoke.sh <IP>`.

## 🧑‍💼 Access Control & User-Specific Commands

Siglatch supports scoped command execution based on the authenticated user's key. Each client key (or key ID) can be associated with a predefined menu of allowed operations, enabling flexible yet secure delegation of actions.

- The daemon will maintain a per-key **access control list (ACL)** mapping key IDs to permitted commands.
- Clients may request any command from their permitted list, or a fallback/default action if none is specified.
- This enables safe multi-user deployments where each authorized user may unlock different capabilities.
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

## ⚙️ Configuration & Extensibility (Stub)

- Sequence timing (X knocks in Y seconds)
- Knock actions (default command per user/key)
- Timeout durations
- Script paths and allowed commands

## 🧩 Source Layout

```
siglatch-project/
├── knock/
│   └── main.c              # Client
├── siglatch/
│   └── main.c              # Daemon
├── scripts/
│   ├── knock_grant.sh
│   └── knock_revoke.sh
├── src/
│   └── test/
│       └── any.c           # Scratch/testing
├── Makefile
└── README.md
```

## ⚠️ Operational Considerations

- Must run as root (or with appropriate `CAP_NET_ADMIN`)
- `iptables` commands must be trusted
- Daemon should **not echo** any response over UDP
- Always maintain a **manual fallback (backdoor server)**

## 📅 Next Steps (Working Plan)

1. ✅ Build and test basic knock + daemon interaction
2. ✅ Add keepalive support and session expiry logic
3. 🧪 Test auto-revoke logic after timeout
4. 🔐 Harden knock messages with timestamp and HMAC
5. 📦 Wrap firewall calls in hardened shell scripts
6. 🔁 Optionally: build retry/resend/keepalive loop in knock client
