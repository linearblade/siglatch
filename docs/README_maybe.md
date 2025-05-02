# 📖 README.md — `siglatch`

## 🔒 Project Overview

**Siglatch** is a secure, stealthy, UDP-based access daemon built for remote infrastructure management in hostile network environments.

It draws inspiration from port knocking, encrypted messaging, and dead drop mechanics to:
- **Control access** without exposing traditional open ports.
- **Authenticate commands** securely with layered encryption and HMAC validation.
- **Enable flexible operations** via scriptable hooks, user action controls, and future menu-driven services.

Designed with security, operational flexibility, and minimal visibility in mind, **siglatch** provides:
- Temporary and revocable network access.
- Hardened packet validation against replay and tampering.
- Options for stealth deployment (no logs, no responses).
- Room for future expansions (server-to-client replies, larger data payloads, anonymous communication).

> **One packet to rule them all.**

This project prioritizes **robustness**, **usability**, and **survivability** in unpredictable or adversarial network conditions.

---

## 🌎 Real-World Use Cases

Siglatch is designed to enable or disable access to sensitive areas without relying on bulky VPN infrastructure. Examples include:

- **SSH Access Management**:
  - Grant or revoke specific IP addresses the ability to SSH into critical systems.
  - Still requires SSH keys for actual authentication.
  - Perfect for users with shifting IP addresses (public Wi-Fi, mobile hotspots, etc.) or in untrusted networks.

- **Web Service Control**:
  - Enable or disable sensitive web services (admin panels, local database interfaces, etc.) on demand.
  - Useful for protecting temporary windows of access without exposing services permanently.

- **Dead Drop Communication** (future expansion):
  - Leverage dead drop mode for lightweight, low-profile communication.
  - Potential applications for anonymous tip lines, whistleblower reporting, or covert data exchanges.
  - Minimized metadata exposure compared to traditional messaging systems.

In short: all the stuff you want to do securely and surgically **without the bloated complexity, constant babysitting, or heavy footprint of traditional VPNs**.

---

## 📚 Documentation

- [⚙️ OPERATIONS.md](./OPERATIONS.md) — How to install, configure, run, and maintain siglatch.
- [📦 FEATURES.md](./FEATURES.md) — Full feature specification (current and planned).
- [🔐 SECURITY.md](./SECURITY.md) — Security model, mitigations, and threat considerations.

Please read the above documents carefully to understand setup procedures, operational safety, and future plans.

---

## 🧠 Final Notes

This project is under active development.  
Expect rapid improvements, especially around:
- Interactive client features.
- Server-to-client encrypted messaging.
- Dynamic system management (emergency sleep/shutdown controls).
- Expanded operational tooling.
- Dead drop communication support for lightweight, potentially anonymous exchanges.

---

*Siglatch is built for operators who need control, security, and minimal exposure.*

---

(Updated: 2025)

