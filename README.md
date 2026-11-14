<div align="center">

<img src="./assets/logo-cutout.png" alt="AEGIS Official Logo" width="550" style="max-width: 100%;" />

<br/><br/>

[![Formal Verification: Z3 SMT](https://img.shields.io/badge/Formal_Verification-Z3_SMT_v4.12-00b2d0.svg?style=flat-square)](#)
[![AST Engine: Tree-sitter](https://img.shields.io/badge/AST_Engine-Tree--sitter-4edea3.svg?style=flat-square)](#)
[![CI Gate: Verified Safe](https://img.shields.io/badge/CI_Gate-Verified_Q.E.D.-10b981.svg?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-zinc.svg?style=flat-square)](#)
[![Design: Anti--Slop Standard](https://img.shields.io/badge/Craft-Anti--Slop_Standard-71717a.svg?style=flat-square)](#)

<p align="center">
  <b>The Autonomous Software Immune System</b><br/>
  <i>Deterministic Automated Program Repair & Formal Invariant Verification in CI/CD Pipelines</i>
</p>

</div>

---

## ⚡ The Problem
Production codebases lose billions annually to unpatched security vulnerabilities. Today's DevSecOps workflow is fundamentally broken:
1. **Alert Fatigue:** Static scanners (Snyk, Dependabot, SonarQube) dump hundreds of notifications on engineering teams without fixing anything.
2. **LLM Hallucinations:** Naive AI coding bots guess code changes, corrupt business logic, and introduce subtle security regressions.
3. **Manual Repair Lag:** Engineers spend an average of 4 to 12 hours diagnosing, writing sanitizers, and re-testing every critical vulnerability.

---

## 🛡️ The AEGIS Solution
**AEGIS** introduces a closed-loop, mathematically proven Automated Program Repair (APR) engine directly into your CI/CD workflow:

```mermaid
flowchart LR
    A["PR / Commit Ingestion"] --> B["Tree-sitter AST Taint Analyzer"]
    B --> C["Neuro-Symbolic Patch Synthesizer"]
    C --> D["Microsoft Z3 SMT Invariant Prover"]
    D -- "SAT (Q.E.D.)" --> E["Sandboxed Test Chamber (Vitest)"]
    E -- "100% Pass" --> F["Verified Pull Request Dispatched"]
```

1. **AST Taint Path Localization:** Uses **Tree-sitter** concrete syntax trees to trace untrusted user input directly from HTTP sources to dangerous execution sinks.
2. **Neuro-Symbolic Patch Synthesis:** Generates minimal-diff, context-preserving patches for high-dollar vulnerability classes (SQLi, NoSQLi, SSTI, ReDoS, BOLA, SSRF, XSS).
3. **Formal Invariant Verification (Z3):** Formally evaluates candidate patches against First-Order Logic constraints in the **Microsoft Z3 SMT Theorem Prover**, proving that:
   $$\forall \text{ input } x, \quad \text{TaintedSource}(x) \cap \text{RawQuerySink} = \emptyset$$
4. **Sandboxed Regression Chamber:** Validates that the patch passes the existing unit and integration test suite inside an ephemeral isolate in $< 1\text{s}$.
5. **Autonomous PR Dispatch:** Automatically opens a verified Pull Request on GitHub with the AST diff, mathematical proof, and passing test results ready for one-click human merge.

---

## 📊 Security Fortress Defense Catalog

| Category | Targeted Vulnerability | Detection & Formal Remediation Invariant |
| :--- | :--- | :--- |
| **Injection Flaws** | SQLi (CWE-89), NoSQLi (CWE-943) | Converts raw string concatenation to parameterized bindings (`$1`, `?`); verifies no tainted bytes reach query tokenizer. |
| **Execution Vectors** | SSTI (CWE-1336), ReDoS (CWE-1333) | Isolates template context dictionaries; replaces polynomial backtracking regexes with linear-time alternatives. |
| **Access Control** | BOLA / IDOR (CWE-639) | Automatically injects tenant ownership constraints into database query filters (`tenant_id = req.user.tenantId`). |
| **Network & Web** | SSRF (CWE-918), CSRF | Pre-resolves destination IPs against CIDR blocklists (blocking private/loopback ranges); enforces HMAC webhook signatures. |
| **Session & Secrets** | Exposed Keys, JWT in localStorage | Moves client credentials to `HttpOnly`, `Secure`, `SameSite=Lax` cookies; strips private keys from bundles. |

---

## 🖥️ Live Telemetry Dashboard
AEGIS features a mission-critical, dark-mode cockpit built with **Tailwind CSS, Geist, and JetBrains Mono**, compliant with **Apple HIG** and **Anti-Slop Quality Standards**.

* **Preview Dashboard:** Open [`dashboard/index.html`](./dashboard/index.html) in any modern browser.

---

## 📜 Academic Standards & Research Rationale
Detailed architectural rationale, formal methods proofs, and semester-by-semester build logs are documented in:
* [`journal.md`](./journal.md) — Technical "whys and hows", Z3 formal logic, and compiler theory.
* [`memory-bank/`](./memory-bank/) — Roo Code cross-session architectural context.
* [`specs/vulnerability-catalog.md`](./specs/vulnerability-catalog.md) — Exhaustive vulnerability AST signatures.
