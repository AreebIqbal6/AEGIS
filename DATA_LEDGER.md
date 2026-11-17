# AEGIS Data Ledger
*Governed by AGENTS.md — strict provenance tracking for every screen, claim, and metric.*

| Screen / UI Component | Metric / Claim | Displayed Value | Provenance Tag | Actual Source / Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Top Navigation** | Server & DB Status | `SQLite: Live (sample-app/data/app.db)` | `[LIVE]` | Real SQLite database file created with `better-sqlite3`, seeded with test users. |
| **Top Navigation** | GitHub Pull Request | `PR #1: Open (Awaiting Review)` | `[LIVE]` | Live PR created via GitHub CLI: https://github.com/AreebIqbal6/AEGIS/pull/1 |
| **Incident Hero** | Target Vulnerability | `CWE-89: SQL Injection` | `[LIVE]` | Real vulnerable string concatenation in `sample-app/src/auth.ts:15`. |
| **Incident Hero** | Target Location | `sample-app/src/auth.ts:15` | `[LIVE]` | Located precisely at line 15, col 15 by Tree-sitter CST traversal. |
| **Incident Hero** | Severity Score | `CRITICAL (CVSS 9.8)` | `[LIVE]` | Industry standard CVSS v3.1 vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. |
| **Incident Hero** | Formal Proof State | `Formal Proof: Not Implemented` | `[NOT IMPLEMENTED]` | Scope boundary per AGENTS.md: Z3 SMT solver is not wired to this build; no fake proofs. |
| **Telemetry Card** | Test Execution Latency | `158.5 ms` | `[LIVE]` | Measured execution duration of `node --test sample-app/dist/test/auth.test.js`. |
| **Telemetry Card** | Total Pipeline Latency | `3,033.7 ms` | `[LIVE]` | Measured duration covering AST parsing, patch generation, TypeScript compile, and test run. |
| **Telemetry Card** | Test Suite Status | `4 / 4 Passing (100%)` | `[LIVE]` | 3 functional auth tests + 1 adversarial injection attack test executed in Node.js test runner. |
| **Surgery Editor** | Diff View | Real Unified Diff | `[LIVE]` | Computed via `PatchGenerator` AST transformation using `diff` library. |
| **Surgery Editor** | Offending Code | Line 15 string concat | `[LIVE]` | Extracted directly from `sample-app/src/auth.ts`. |
| **Surgery Editor** | Parameterized Fix | `.prepare("... WHERE id = ?").get(userId)` | `[LIVE]` | Real patch synthesized by AST rewriter and verified regression-free. |
| **Test Chamber** | Alice Admin Auth | `✔ Passed (1.16ms)` | `[LIVE]` | Real assertion verifying valid admin credential resolution. |
| **Test Chamber** | Bob User Auth | `✔ Passed (0.29ms)` | `[LIVE]` | Real assertion verifying standard user credential resolution. |
| **Test Chamber** | Ghost User Null | `✔ Passed (0.23ms)` | `[LIVE]` | Real assertion verifying `undefined` returned for nonexistent users. |
| **Test Chamber** | Adversarial SQLi Check | `✔ Passed (0.23ms)` | `[LIVE]` | Exploit payload `' OR '1'='1` blocked: query treats payload as literal ID, returns `undefined`. |
| **Exploit Simulator** | Adversary Payload | `' OR '1'='1` | `[LIVE]` | Evaluated against actual SQLite engine behavior before and after patch. |
| **Pull Request** | GitHub Integration | PR #1 | `[LIVE]` | Opened on branch `aegis/fix-cwe89-sqli-mwkgsz0j` via `gh pr create` with test output attached. |
| **Pull Request** | Auto-Merge | `Disabled` | `[NOT IMPLEMENTED]` | Scope boundary: AEGIS creates PRs for human review; autonomous merging is strictly forbidden. |
| **Memory Hotpatch** | In-memory Live Patch | N/A | `[NOT IMPLEMENTED]` | Scope boundary: Live process memory patching is out of scope. Every fix becomes a PR. |
| **Roadmap Scenarios**| CWE-79 (XSS) | Seed demonstration | `[SEED/DEMO DATA]` | Demonstration scenario for roadmap. Not yet wired to tree-sitter pipeline. |
| **Roadmap Scenarios**| CWE-918 (SSRF) | Seed demonstration | `[SEED/DEMO DATA]` | Demonstration scenario for roadmap. Not yet wired to tree-sitter pipeline. |
