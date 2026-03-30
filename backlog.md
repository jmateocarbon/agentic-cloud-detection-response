# 🛡️ Agentic CDR: Security Engineering Roadmap

This roadmap tracks the hardening and architectural evolution of the CVE-to-MITRE mapping engine.

---

## Completed (Security Baseline)
* [x] **Supply Chain Integrity**: All GitHub Actions pinned to **SHA-256 hashes** instead of mutable tags (e.g., `@v4`) to prevent tag-flipping attacks.
* [x] **Budget & Token Gating**: Implemented the `agentic_cdr` environment with a **Manual Reviewer** requirement to prevent unauthorized API spend on PRs.
* [x] **Least Privilege CI/CD**: Globally restricted `GITHUB_TOKEN` to `contents: read`, with `security-events: write` granted only to the CodeQL job.
* [x] **Test Automation**: Resolved Pytest discovery issues and integrated automated testing into the secure pipeline.

---

## High Priority (P0) — Identity & Data Protection
* [ ] **OIDC Implementation**: Transition from static `GENERIC_API_KEY` to **Workload Identity Federation** (Keyless auth) for GCP/Gemini access.
* [ ] **Data Sanitization**: Implement a regex-based "Scrubbing" layer to strip PII and internal identifiers (IPs, Hostnames) from data before AI analysis.
* [ ] **Binary Verification**: Implement SHA-256 hash pinning for any security binaries used in the pipeline (e.g., `bandit`, `semgrep`).
* [ ] **Human/Machine Readable Reports**: Transition output from raw `.txt` reasoning logs to structured `JSON` (machine) and `PDF/CSV` (human).

---

## Medium Priority (P1) — Architecture & Intelligence
* [ ] **Contain and Ship (Docker)**: 
    * Draft a **multi-stage, non-root Dockerfile** using `python:3.11-slim` to minimize the attack surface.
    * Integrate a container vulnerability scan into the GHA pipeline using a SHA-pinned scanner.
* [ ] **Correlation Logic**: Develop logic to cross-reference assets appearing in both audit logs and vulnerability scans to identify "Active" threats.
* [ ] **Search Redundancy**: Trigger secondary, more specific search queries if Agent C returns an "Uncertain" status to resolve hallucinations.

---

## Low Priority (P2) — Persistence & Delivery
* [ ] **Report Persistence (Deduplication)**: Implement file hashing (SHA-256) for input fixtures to ensure the AI doesn't re-process (and charge for) unchanged data.
* [ ] **Notification Delivery**: Integration with reporting tools (Slack/Email) specifically for "Verified" high-confidence mappings.

---
*Last Updated: 2026-03-30*