# Memory Bank: Product Context
<!-- Problems Solved, Intended User Experience, and Value Proposition -->

## Problems Solved
1. **The Vulnerability Triage Bottleneck:** Static Application Security Testing (SAST) tools like Snyk, SonarQube, and Dependabot generate thousands of warnings, but leave the actual code remediation to human engineers. Triaging and patching takes hours or days per vulnerability.
2. **LLM Hallucinations in Automated Code Fixes:** Blind code generation tools (like naive GitHub Copilot autofix) hallucinate syntax, change unrelated business logic, or introduce regression bugs.
3. **Compliance & Audit Friction:** Regulated industries (FinTech, HealthTech, GovTech) cannot adopt autonomous tools that lack verifiable mathematical proofs and rigorous audit logs.

## Intended User Experience
* **Zero Disruption Workflow:** Developers push a commit or open a Pull Request on GitHub.
* **Autonomous Remediation:** If a security regression or vulnerability is detected, AEGIS analyzes the AST, generates a parameterized/sanitized fix, proves its safety in Z3, runs the test suite in < 30 seconds, and posts a verified PR.
* **One-Click Merge:** The developer reviews the visual AST diff, inspects the Q.E.D. formal invariant badge, and merges with complete confidence.
