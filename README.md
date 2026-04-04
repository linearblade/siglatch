# 📖 README.md — `siglatch`

[![Siglatch Logo](./logo.png)](https://github.com/linearblade/siglatch)

> [!WARNING]
> `2.0-dev` is a development release.
> For stable production use, pin to the `1.0` tag.

## 🔒 Project Overview

**Siglatch** is a lightweight, configurable, encrypted UDP control bus for remote infrastructure.

It provides:

* Builtin actions for hot reloads and live reconfiguration
* Plugin-style execution via shell scripts, static objects, or dynamic objects
* Policy controls for IP allowlists, user gating, action gating, and wire validation
* Full-duplex authenticated UDP transport with user-defined protocol families and protocol demux
* Multi-packet support for larger payloads, including stream-like or batched file-style submission

---

## 📌 Roadmap

* This project is under active development.
* Current version: `2.0-dev`.
* Stable version: see tag `1.0`.
* `v1`: single-packet RSA-2048 encrypted transport.
* `v2`: stateless hybrid transport with full-duplex multi-packet payload support.
* `v3`: (projected) DTLS-based session transport with QUIC/HTTP/3 support and commercial-grade polish.

---

## 📚 Documentation
These guides are being actively updated, check back often for updates!
* [📦 FEATURES](docs/FEATURE_SPEC.md) — Full feature specification (current and planned).
* [📝 CHANGELOG (2026-03-12)](docs/CHANGELOG_2026-03-07.md) — Recent development changes since `1.0`.
* [🔐 SECURITY](docs/SECURITY.md) — Security model, mitigations, and threat considerations.
* [🌎 USE CASES](docs/USE_CASES.md) — Common deployment patterns and examples.
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

*Siglatch is built for operators who need control, security, and minimal exposure.*

---

* 🔒 This project is licensed under the [**MTL-10 License**](LICENSE.md)
* 🧑‍💻 [Free for use by teams with ≤10 users](USE_POLICY.md)
* 💼 Commercial, resale, or SaaS use requires a license  
* 📩 Contact: legal@m7.org

(Updated: 2025)
