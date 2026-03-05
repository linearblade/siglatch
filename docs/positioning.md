# 🚀 Siglatch: The Lightweight Encrypted Access Bus

## 🔐 What Is Siglatch?

Siglatch is a lightweight, cryptographically secure UDP daemon that acts as a **surgical control bus** for servers, daemons, and internal infrastructure. It provides signed, authenticated, shell-free remote command dispatch with near-zero overhead—making it ideal for environments where speed, control, and minimalism matter most.

It replaces fragile cron glue, log tunnels, VPN-based access gates, and HTTP command APIs with a single encrypted packet.

---

## 🌍 Where Siglatch Fits

Siglatch competes not with traditional port knockers—but with:

* Agent-based automation tools (SaltStack, Ansible, Rundeck)
* Zero-trust gateways (Teleport, Boundary)
* Internal control APIs (cron + curl + bash)
* Log and task daemons (rsyslog, cron, systemd timers)

It delivers the same control—**without agents, HTTP, SSH, or REST**.

---

## 🧠 Why Choose Siglatch?

### ✅ Lightweight Footprint

* Single binary daemon
* \~6 MB memory usage
* One-way UDP messages, no sockets to manage

### ✅ Encrypted & Authenticated

* Crypto signatures verify every sender
* Public-key-based authorization
* Works airgapped or over insecure links

### ✅ Shell-Free Execution

* No `fork()`, no `execve()`
* Commands handled inline in C (or `.so` plugins coming soon)
* Lightning-fast dispatch (<1ms typical)

### ✅ Drop-In Versatility

* Log forwarding
* Job scheduling
* Access toggling
* Config reloading
* Secure messaging
* Cron replacement

---

## 🥊 Competitive Positioning

| Category           | Traditional Tools             | Siglatch                      |
| ------------------ | ----------------------------- | ----------------------------- |
| Automation         | Ansible, SaltStack            | ✅ Encrypted commands via UDP  |
| Secure Access      | VPN, SSH, Teleport            | ✅ Inline access toggles       |
| Job Scheduling     | cron, systemd timers          | ✅ Signed job dispatch         |
| Logging            | syslog, rsyslog, log shippers | ✅ Stateless log push          |
| Metadata Footprint | High                          | ✅ Minimal trace, no TLS layer |
| Dependencies       | Python, Ruby, web servers     | ✅ Just C, sockets, and crypto |


