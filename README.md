# Agentic Security Pod (v1.0)
A stateless, AI-orchestrated pipeline designed to enrich raw security alerts into verified remediation intelligence for your cloud and infrastructure assets. 

## Table of Contents
* [Overview](#overview)
* [Disclaimer & API Limits](#disclaimer--api-limits)
* [Deployment Strategy](#deployment-strategy)
* [Architecture & Personas](#architecture--personas)
* [Diagram](#diagram)
* [Project Structure](#project-structure)
* [Run Tests](#run-tests)
* [Sample Results](#sample-results)
  * [Vulnerability Enrichment](#vulnerability-enrichment)
  * [Output](#output)
* [Self Audit Snippet](#self-audit-snippet)

## Overview
This system utilizes a multi-agent LLM architecture to analyze security findings. Unlike legacy automation tools, it leverages live search and multi-stage verification to ensure remediation advice is grounded in the most current threat intelligence, including CISA KEV status and MITRE ATT&CK TTPs.

## Disclaimer & API Limits
This serves as a guiding Proof of Concept (POC) for vulnerability enrichment and detection response using AI agents. 

**Note on API Quotas:** The Pod processes multiple agentic calls per alert. If you are operating on a free or trial API tier, you may hit rate limits (e.g., HTTP 429 errors or quota caps) during large batch processing runs. Upgrading to a Pay-as-you-go billing tier is recommended before pushing a massive backlog through the pipeline. 

## Deployment Strategy
Before running this in production, it is highly recommended to implement a logging and aggregation layer. 
1. Deploy a log management solution (e.g., ELK Stack / OpenSearch).
2. Create filters and aggregation rules to group duplicate alerts.
3. Feed the deduplicated, high-fidelity JSON findings into this Pod's ingestion directories.

## Architecture & Personas
The Pod operates on a strict separation of duties, utilizing four specialized agent personas:
* **Agent A (CVE Expert):** Technical vulnerability researcher focusing on software supply chain and patching.
* **Agent B (Cloud Architect):** Infrastructure specialist hunting for IAM toxic combinations and Storage misconfigurations.
* **Agent C (Verifier):** Stateless live-search enrichment. Validates the claims of Agents A & B against live data (CISA KEV, MITRE) to prevent LLM hallucinations.
* **Agent D (Self-Auditor):** Internal integrity controller. Runs a native SAST scan (`bandit`) on the Pod's core engine prior to execution to prevent tampering and logic flaws.

## Diagram
![Agentic Architecture](/images/diagram.jpg) 


## Project Structure
```text
.
├── agentic_cdr.py           # Core execution engine
├── personas/                # Externalized agent logic (.md)
├── detections/              # LIVE INGESTION
│   ├── vulnerability/       # Drop CVE JSONs here
│   └── audit/               # Drop Cloud Misconfig JSONs here
├── scan_reports/            # LIVE OUTPUT
│   ├── agentic_scans/       # Verified remediation reports
│   └── self_scan/           # Pre-flight SAST & integrity logs
└── tests/                   # ISOLATED TEST ENVIRONMENT
    ├── run_tests.py         # Test execution script
    ├── fixtures/            # Mock JSON payloads
    └── output/              # Isolated test results
```



## Sample Results
### Vulnerability Enrichment
```json
{
  "source": "Hoken Cloud SCC",
  "data": {
    "category": "vulnerabilities",
    "asset_name": "//compute.googleapis.com/projects/company-internal/zones/us-central1-a/instances/legacy-gateway",
    "finding_id": "SCC-VULN-HTTP2-RESET",
    "vulnerability_id": "CVE-2023-44487",
    "severity": "High",
    "description": "HTTP/2 Rapid Reset Attack vulnerability (CVE-2023-44487) detected via network scanning of the instance endpoint.",
    "resource_type": "google.compute.Instance",
    "location": "us-central1-a",
    "remediation_steps": "Update the web server software to the latest version and apply vendor patches for HTTP/2."
  }
}
```
### Output
```json
{
  "investigation_status": "VERIFIED",
  "vulnerability": {
    "cve_id": "CVE-2023-44487",
    "description": "HTTP/2 Rapid Reset Attack"
  },
  "asset_location": "legacy-gateway (Instance in generic-cloud-region-a)",
  "mitre_attack": {
    "technique_id": "T1499",
    "technique_name": "Endpoint Denial of Service"
  },
  "cisa_kev_status": {
    "is_listed": true,
    "notes": "Included in the CISA Known Exploited Vulnerabilities Catalog. Exploitation was observed in the wild from August through October 2023."
  },
  "developer_context": {
    "mechanism_explanation": "This critical vulnerability exploits the HTTP/2 protocol's stream cancellation mechanism. The exploit works by allowing an unauthenticated remote attacker to rapidly send and immediately cancel a large number of HTTP/2 streams within a single connection. This forces the server to expend significant CPU and memory resources on processing the stream setup and teardown, leading to a complete Denial of Service (DoS) condition on the targeted service.",
    "detection_logic": "Monitor for an unusually high volume of HTTP/2 RST_STREAM frames and connection resets originating from single client IP addresses within a short time window."
  },
  "remediation": {
    "recommended_action": "Apply the latest security patches for the specific web server or proxy to implement rate limiting on HTTP/2 RST_STREAM frames.",
    "target_version": "Refer to specific vendor advisories for patched versions."
  }
}
```

## Self Audit Snippet
#### Bandit Status: PASSED 
#### Agent Analysis:
1.  **Command Injection/Subprocess Calls (`secure_shell_tool`):**
    *   `shell=False` is correctly enforced in `subprocess.run`.

2.  **File Handling/Path Traversal:**
    *   `ensure_dirs()` uses `os.makedirs(..., exist_ok=True)`, which is safe.

5.  **Self-Audit Logic:**
    *   The `run_self_audit` function correctly executes a native, local `bandit` scan using `shell=False` and compares the results against the LLM's analysis, failing hard if the LLM reports a critical blocker during the pre-flight check.

The code demonstrates sound security practices concerning external command execution, input sanitization, and file path construction.

Self-Audit Passed.

## Run Tests     
[Hallucination Tests](/tests/TEST_CASES.md) 
```bash
python run_tests.py
```
