# Memory Bank: Project Brief
<!-- Core Requirements, Academic Mission, and Project Goals -->

## Project Identity
* **Name:** AEGIS (Autonomous Engine for Program Vulnerability Repair and Formal Invariant Verification in CI/CD Pipelines)
* **Target Audience:** Engineering teams, DevSecOps architects, enterprise compliance officers, and university academic evaluation panels.
* **Timeline:** 5th Semester to 8th Semester Software Engineering Final Year Project (FYP).

## Core Requirements
1. **Automated Taint & Vulnerability Localization:** Parse target source code into Abstract Syntax Trees (ASTs) using Tree-sitter, identify tainted data-flow paths from HTTP sources to critical sinks.
2. **Autonomous Patch Synthesis:** Generate surgical, context-preserving patches for high-dollar vulnerability classes (SQLi, NoSQLi, SSTI, ReDoS, BOLA, SSRF, XSS).
3. **Formal Invariant Verification (Z3):** Verify patch correctness using First-Order Logic constraints in the Microsoft Z3 SMT Theorem Prover before test execution.
4. **Sandboxed Regression Testing:** Validate that the patch passes existing unit and integration test suites in an isolated sandbox.
5. **CI/CD Integration & PR Dispatch:** Package as a GitHub App / Action that comments on PRs with the formal proof, AST diff, and passing test results.
6. **High-Craft Telemetry Dashboard:** Provide a mission-critical dark mode cockpit adhering to Apple HIG, Linear/Vercel design craft, and anti-slop guidelines.
