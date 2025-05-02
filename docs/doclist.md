⸻

🧾 Appropriate Product Documents for This Project

1. Feature Specification ✅ (you already started this)
	•	Audience: You, contributors (if any), future you
	•	Focus: What it does, how it does it, and the system behavior
	•	Example: FEATURES.md

This is exactly what you’re maintaining now — excellent format for defining features and tracking progress.

⸻

2. Technical Design Document (TDD) 🧠
	•	Audience: Technical reviewers, engineers (future you again)
	•	Focus: Implementation-level choices, architecture decisions, edge case handling, thread-safety, race conditions, etc.
	•	Example: How sessions are cleaned up, HMAC calculated, daemon lifecycles managed

Could be named design.md, architecture.md, or docs/tdd.md.

⸻

3. Security Threat Model 🔐 (optional but highly valuable here)
	•	Audience: You, possibly security auditors
	•	Focus: Threats, attacker capabilities, mitigations, trust boundaries
	•	Example: Replay protection, spoofing, MITM on Starlink uplink

Use something like STRIDE if formal, or just a clean Markdown table if informal.

⸻

4. Operational Playbook / Runbook 🔧 (super useful)
	•	Audience: You during production and panic mode
	•	Focus: How to deploy, restart, diagnose, emergency steps, logs
	•	Example: “How to manually revoke an IP”, “How to restart knocker safely”

Name it: RUNBOOK.md, OPERATIONS.md, etc.

⸻

5. README.md 📘
	•	Audience: Anyone browsing the repo
	•	Focus: Short overview, quickstart, how to compile/use
	•	Your current one can stay lean, linking to FEATURES.md, docs/, etc.
