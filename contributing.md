# Contributing to the Agentic Security Pod

First off, thank you for considering contributing to the Agentic Security Pod! It's people like you who make open-source security tools better for everyone.

## Our Security-First Philosophy
This tool is designed to process highly sensitive vulnerability data. Therefore, all contributions must adhere to our "Defense-in-Depth" and "Zero-Trust" principles. 

Before submitting a Pull Request, please ensure your code does not introduce:
1. **Unsanitized inputs** (Always use `shlex` for subprocesses).
2. **Hardcoded secrets or API keys**.
3. **Automated binary execution** without a manual approval gate.

## How to Contribute

### 1. Check the Backlog
Take a look at our `backlog.md`. If you see an open P0, P1, or P2 task that you'd like to tackle, drop a comment or open an issue stating your intent so we don't duplicate work.

### 2. Local Setup
1. Fork the repository.
2. Clone your fork locally.
3. Install the dependencies: `pip install -r requirements.txt`.
4. Create a new branch: `git checkout -b feature/your-feature-name`.

### 3. Testing Your Changes
Before opening a Pull Request, please validate your logic against the scenarios outlined in `TEST_CASES.md`. 
* If you are modifying Agent A, B, or C, ensure the `_UNCERTAIN_` protocol still triggers correctly on ambiguous data.
* If you are modifying the core execution engine, verify that Agent D (Self-Auditor) still passes the pre-flight check.

### 4. Submitting a Pull Request
* Clearly describe the problem you are solving in the PR description.
* Link to any relevant open issues.
* Ensure your code matches the existing style and includes adequate error handling.

## Code of Conduct
By participating in this project, you agree to maintain a respectful, inclusive, and professional environment. Rare request but for pentesting activities, please send it to me privately for any critical results.