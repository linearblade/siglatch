# 🚧 Planned Features for Siglatch Daemon

This document outlines upcoming enhancements and architectural goals for the `siglatchd` secure command and communication daemon.

---

## 🔑 Security Enhancements

### IP-Based Rate Limiting & Blacklisting

* Throttle repeated connection attempts per IP.
* Temporarily or permanently block abusive clients.

### Key Exchange Protocols

* Support server-to-client communication for:

  * Secure delivery of HMAC or public keys.
  * Optional automatic provisioning of user credentials.

### Decoy Packet Sending

* Emit fake or misleading packets to confuse attackers.
* Optional configurable frequency and type.

---

## 👥 User & Access Management

### Guest / Anonymous Onboarding

* Allow dynamic creation of temporary keys for one-time access.
* Optional approval flow or time-based expiration.

### Time-Limited Keys / Sessions

* Auto-expire keys after a set usage count or time duration.
* Useful for scheduled or temporary access policies.

---

## 🌐 Server Behavior & Networking

### Multi-Server Coordination

* Allow multiple instances to coordinate via shared config/state.
* Potential for clustered deployments or redundancy.

### Multi-Port Listening

* Enable services to listen on several ports.
* Implement port-knocking-style behavior for stealth entry.

### Multi-Packet Payloads & Relays

* Support transmission of large payloads split across packets.
* Add relay logic to pass through or forward client requests.

### Server Privilege De-escalation

* Drop root privileges before executing scripts.
* Support execution under dedicated unprivileged users.

---

## ♻️ Live Configuration Features

### HOT Reload & Runtime Commands

* Support live reloading of config files without restart.
* Allow admin-issued runtime commands such as:

  * `reload`
  * `enable/disable` servers or actions
  * `broadcast` messages to clients
  * `list available actions`

### System Message Delivery

* Lightweight message-push mechanism for clients to receive

  * Notices
  * Warnings
  * Available feature info

---

## 💡 Additional Core & Operational Enhancements

### Config Validation & Linting

* Detect invalid or ambiguous entries on daemon start or reload.
* Warn about duplicate or unused actions, users, or servers.

### Test Mode / Dry Run

* Simulate daemon behavior without executing actions.
* Useful for CI pipelines or pre-deployment verification.

### Batching or Streaming Payloads

* Accept multiple commands in a single session.
* Output progress or response as an event stream.

### Client Challenge-Response Handshake

* Optional handshake before accepting commands.
* Confirms identity or readiness of client before processing.

### Interactive Admin Shell / CLI

* Allow runtime control of the daemon via a secure shell.
* Issue commands, inspect logs, or reload configurations live.

### Plugin or Module System

* Dynamically load new actions or handlers from file.
* Support shell scripts, compiled binaries, or shared object modules.

### Auto-Rotation of Keys

* Rotate server or user keys on a timed schedule.
* Notify or push updated public keys to clients.

---

## 🧱 Future Work

* Integrate with external service discovery / auth providers.
* Encrypted storage of keys (e.g., Vault integration).
* Web-based admin dashboard for observability and control.
