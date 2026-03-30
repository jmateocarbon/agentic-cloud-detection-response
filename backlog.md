# Project Backlog

I want to track and record ideas on my head on how to harden this project as a engineering roadmap.

## High Priority (P0)
- Data Sanitization: Implement regex scrubbing to remove specific identifiers before performing live web searches.
- Supply Chain Hardening: Considering doing live checks for compromises to libraries used.
- Binary Verification: Implement SHA-256 hash pinning for whitelisted security binaries for tools like bandit and semgrep
- Human/Machine Readable Reports: Currently in .txt, need to change to email, pdf or csv.

## Medium Priority (P1)
- Correlation Logic: Develop logic to flag assets that appear in both audit and vulnerability scan folders, improve hallucinations.
- Search Redundancy: Implement automated secondary search queries if Agent C returns an uncertain status.
- Automated tests: Add gitactions for test, I still use free tier, so not yet.

## Low Priority (P2)
- Notification Delivery: Integration with reporting tools
- Report Persistence: Implement file hashing to prevent redundant processing of existing alerts.