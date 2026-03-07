# 📖 README.md — `siglatch`

> [!WARNING]
> `v1.1` is a development release.
> For stable production use, pin to the `1.0` tag.

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

Siglatch is designed to **securely enable or disable access to sensitive services**—without relying on bloated VPNs, heavyweight web stacks, or shell hacks.

Examples include:

---

* **SSH Access Management**  
  Grant or revoke specific IPs the ability to SSH into critical systems.  
  Still uses SSH keys for authentication—Siglatch simply decides *who gets to knock*.  
  Ideal for mobile users, dynamic IPs, and zero-trust environments.

---

* **Web Service Control**  
  Securely toggle access to local dashboards, admin panels, or internal UIs.  
  Services stay hidden until explicitly enabled, reducing attack surface.

---

* **Dead Drop Communication** *(live)*  
  Stateless encrypted payload exchange—no sessions, no metadata.  
  Useful for whistleblowing, anonymous tips, or passive covert delivery.  
  Siglatch handles this natively with one-way crypto-authenticated packets.

---

* **Interserver Signaling & Command Dispatch**  
  Push secure instructions (e.g., `reload`, `rotate`, `notify`) between daemons.  
  Acts as a low-latency, authenticated internal control bus.  
  Ideal for config sync, health triggers, and lightweight orchestration.

---

* **Log Forwarding & Job Scheduling**  
  Replace fragile syslog chains and scattered `cron` jobs with centralized, secure triggers.  
  Log events and timed actions can be dispatched with encrypted, low-cost Siglatch messages.

---

* **Inline C Plugin Support** *(coming soon)*  
  Drop in `.so` modules to handle requests **without shelling out or restarting the daemon**.  
  Achieve sub-millisecond response times for logs, access gates, or custom handlers.

---

In short: **everything you want to control surgically and securely—without the babysitting, overhead, or footprint of traditional VPNs, HTTP servers, or orchestration systems.**

---

## 📚 Documentation
These guides are being actively updated, check back often for updates!
* [📦 FEATURES](docs/FEATURE_SPEC.md) — Full feature specification (current and planned).
* [📝 CHANGELOG (2026-03-07)](docs/CHANGELOG_2026-03-07.md) — Recent development changes since `1.0`.
* [🔐 SECURITY](docs/SECURITY.md) — Security model, mitigations, and threat considerations.
* ⚙️ **Installation**
  * 🛠️ [**COMPILING**](docs/OPERATIONS_COMPILE.md) — How to build the project from source.
  * 🧾 [**DAEMON_CONFIGURATION**](docs/OPERATIONS_CONFIG.md) — Manual for configuring the server daemon.
  * 📥 [**INSTALLATION**](docs/OPERATIONS_INSTALL.md) — `install.sh` help and setup guide.
  * 📚 [**QUICK START**](docs/OPERATIONS.md) — AFTER you've compiled and configured siglatch!
  * 🖥️ [**CLIENT_OPERATIONS**](docs/OPERATIONS_CLIENT.md) — Detailed instructions for client-side use.
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
