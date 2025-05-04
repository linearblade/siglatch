# 📖 README.md — `siglatch`

## 🔒 Project Overview

**Siglatch** — Tight, scriptable, and cryptographically enforced access controller for connectionless protocols and remote infrastructure management in hostile network environments.

Siglatch enables fine-grained, per-user, per-action control with strong cryptographic authentication — purpose-built for UDP and similar transport layers where traditional session security is impractical or overkill. Designed for environments where **minimalism, determinism, and security** are non-negotiable.

It draws inspiration from port knocking, encrypted messaging, and dead drop mechanics to:

* **Control access** without exposing traditional open ports.
* **Authenticate commands** securely with layered encryption and HMAC validation.
* **Enable flexible operations** via scriptable hooks, user action controls, and future menu-driven services.

Designed with security, operational flexibility, and minimal visibility in mind, **siglatch** provides:

* Temporary and revocable network access.
* Hardened packet validation against replay and tampering.
* Options for stealth deployment (no logs, no responses).
* Room for future expansions (server-to-client replies, larger data payloads, anonymous communication).

> **One packet to rule them all.**

This project prioritizes **robustness**, **usability**, and **survivability** in unpredictable or adversarial network conditions.

---

## 🌎 Real-World Use Cases

Siglatch is designed to enable or disable access to sensitive areas without relying on bulky VPN infrastructure. Examples include:

* **SSH Access Management**:

  * Grant or revoke specific IP addresses the ability to SSH into critical systems.
  * Still requires SSH keys for actual authentication.
  * Perfect for users with shifting IP addresses (public Wi-Fi, mobile hotspots, etc.) or in untrusted networks.

* **Web Service Control**:

  * Enable or disable sensitive web services (admin panels, local database interfaces, etc.) on demand.
  * Useful for protecting temporary windows of access without exposing services permanently.

* **Dead Drop Communication** (future expansion):

  * Leverage dead drop mode for lightweight, low-profile communication.
  * Potential applications for anonymous tip lines, whistleblower reporting, or covert data exchanges.
  * Minimized metadata exposure compared to traditional messaging systems.

In short: all the stuff you want to do securely and surgically **without the bloated complexity, constant babysitting, or heavy footprint of traditional VPNs**.

---

## 📚 Documentation
These guides are being actively updated, check back often for updates!
* [📦 FEATURES](docs/FEATURE_SPEC.md) — Full feature specification (current and planned).
* [🔐 SECURITY](docs/SECURITY.md) — Security model, mitigations, and threat considerations.
* ⚙️ **Installation**
  * 🛠️ [**COMPILING**](docs/OPERATIONS_COMPILE.md) — How to build the project from source.
  * 📥 [**INSTALLATION**](docs/OPERATIONS_INSTALL.md) — `install.sh` help and setup guide.
  * 📚 [**OPERATIONS**](docs/OPERATIONS.md) — General guide for compiling, installing, and running.
  * 🖥️ [**CLIENT_OPERATIONS**](docs/OPERATIONS_CLIENT.md) — Detailed instructions for client-side use.
  * 🧾 [**DAEMON_CONFIGURATION**](docs/OPERATIONS_CONFIG.md) — Manual for configuring the server daemon.
* 📦 **Modules**
  * [🌐 IP_AUTH](docs/modules/IP_AUTH.md) — IP-based authentication module details
* [🧠 AI\_DISCLOSURE](docs/AI_DISCLOSURE.md) — A short note on the use of AI within this project.
* [🚧 PLANNED\_FEATURES](docs/PLANNED.md) — planned and upcoming features
* [🔒 LICENSE](LICENSE.md) — SOFTWARE LICENSE
* [🧑‍💻 USE POLICY](USE_POLICY.md) — USE POLICY

Please read the above documents carefully to understand setup procedures, operational safety, and future plans.

---

## 🧠 Final Notes

This project is under active development.
Expect rapid improvements, especially around:

* Interactive client features.
* Server-to-client encrypted messaging.
* Dynamic system management (emergency sleep/shutdown controls).
* Expanded operational tooling.
* Dead drop communication support for lightweight, potentially anonymous exchanges.

---

*Siglatch is built for operators who need control, security, and minimal exposure.*

---
* 🔒 This project is licensed under the [**MTL-10 License**](LICENSE.md)
* 🧑‍💻 [Free for use by teams with ≤10 users](USE_POLICY.md)
* 💼 Commercial, resale, or SaaS use requires a license  
* 📩 Contact: legal@m7.org

(Updated: 2025)
