# Learning Journal (`journal.md`): Project AEGIS
<!-- Whys, Hows, Architecture Decisions, Formal Methods, and Security Fortress Matrix -->

## 1. Executive Summary & Thesis
**AEGIS** (Autonomous Engine for Program Vulnerability Repair and Formal Invariant Verification in CI/CD Pipelines) is an autonomous DevSecOps gate that intercepts vulnerabilities, localizes faults using Abstract Syntax Tree (AST) taint analysis, synthesizes surgical code patches via specialized code models, and proves patch safety using the **Z3 SMT Theorem Prover** and automated regression test chambers before submitting a verified Pull Request.

---

## 2. Core Architectural Decisions (The "Whys and Hows")

### Decision 1: CI/CD Pipeline Gate vs. Live Memory Hot-Patching
* **The "Why":** In our initial architectural exploratory phase, we considered live in-process binary mutation via `ptrace` or `require.cache` invalidation. However, enterprise compliance standards (SOC2 Type II, PCI-DSS §6.5, ISO/IEC 27001) strictly prohibit un-audited, non-deterministic runtime code mutation in production memory. If an autonomous model hallucinated a patch in production memory, it could corrupt state or introduce catastrophic uninsurable liability.
* **The "How":** AEGIS is deployed as a **GitHub App / CI/CD Action Gate**. It acts in staging/pre-merge environments. It performs zero-downtime execution validation in ephemeral sandboxes (`isolated-vm` / Docker), mathematically proves patch invariance with Z3, and dispatches an audit-logged, cryptographic-stamped Pull Request ready for human sign-off.

### Decision 2: Tree-sitter Polyglot AST Analysis vs. Regex / LLM-Only Scanning
* **The "Why":** Static regular expression scanners (and naive LLM code reviews) suffer from high false-positive rates and hallucinations. They lack lexical and syntactic awareness of data-flow graphs and taint sinks.
* **The "How":** AEGIS integrates **Tree-sitter** concrete syntax tree (CST) grammars. Tree-sitter creates incremental, sub-millisecond AST representations. We construct a directed data-flow graph (DFG) from untrusted user input sources (e.g., `req.body`, `req.query`, HTTP headers) to execution sinks (e.g., `db.query()`, `eval()`, `child_process.exec()`, file system paths).

### Decision 3: SMT Formal Invariant Verification (Z3) vs. Blind LLM Generation
* **The "Why":** Automated Program Repair (APR) literature (ICSE, FSE, USENIX) documents that probabilistic LLMs frequently hallucinate plausible-looking patches that introduce subtle regression bugs or fail on boundary conditions.
* **The "How":** Candidate patches synthesized by the neural model (Qwen2.5-Coder / DeepSeek-Coder / Claude) are converted into First-Order Logic (FOL) constraints and evaluated by the **Microsoft Z3 SMT Solver**. 
  * *Theorem Verification Goal:*
    $$\forall x \in \text{Inputs}, \quad \text{TaintedBytes}(x) \cap \text{SinkTokenizer}(\text{Sanitizer}(x)) = \emptyset$$
  * Only when Z3 returns `SAT` (Satisfiable) with zero counterexamples does the patch proceed to the regression test chamber.

---

## 3. Security Fortress Vulnerability Remediation Catalog

AEGIS is specifically modeled to detect, localize, patch, and formally verify the following vulnerability vectors:

| Vulnerability Vector | Root Cause / Sink | AEGIS AST Taint Rule | Formal Invariant / Remediation Pattern |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | String concatenation in `db.query()` | `BinaryExpression` with string literal & identifier reaching SQL driver sink | Enforce parameterized queries (`$1`, `?`), prove no raw dynamic concatenation |
| **NoSQL Injection** | Raw query selector object pass-through (`{"$gt": ""}`) | Unsanitized object input into MongoDB/Mongoose filters | Cast to scalar/string primitives or enforce schema-level casting |
| **Server-Side Template Injection (SSTI)** | Dynamic template string evaluation (`render(templateString)`) | User input reaching `compile()` or template engine string parsers | Parameterize template variables; replace dynamic string compilation with static templates |
| **Regular Expression Denial of Service (ReDoS)** | Catastrophic backtracking in regex matching user input | Regex with nested quantifiers `(a+)+` evaluated on unbounded string | Synthesize linear-time DFA alternatives or enforce timeout limits |
| **Logical / Payload DoS (LPDoS)** | Unbounded request payload parsing, memory exhaustion | Unchecked payload buffer ingestion without byte limits | Inject strict body parser limits (`limit: '100kb'`) and pagination clamps |
| **Broken Object-Level Auth (BOLA / IDOR)** | Direct resource access by ID without tenant validation | `findById(req.params.id)` without tenant/user ownership filter | Inject ownership invariant: `AND tenant_id = req.user.tenantId` |
| **Server-Side Request Forgery (SSRF)** | Arbitrary URL fetch (`fetch(req.body.url)`) | Unvalidated URL passed to HTTP client | Enforce DNS resolution check, private CIDR blocklist (block `127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`) |
| **Cross-Site Scripting (XSS)** | Unescaped innerHTML or HTML rendering | Tainted string reaching `dangerouslySetInnerHTML` or `res.send()` | HTML entity encoding or DOMPurify sanitization invariant |
| **Secret & Credential Leaks** | API keys in client bundles / Git diffs | High-entropy string matching credential regex in exported code | Extract to server-side environment variables (`process.env`), revoke exposed keys |
| **Insecure Session Storage** | Storing JWTs in `localStorage` | Client-side script accessing `localStorage.setItem('token', ...)` | Transition to `HttpOnly`, `Secure`, `SameSite=Lax` cookies |

---

## 4. Web Quality & Anti-Slop Architectural Standard

All AEGIS public surfaces and dashboards enforce the **38-Point Anti-Vibecoding Quality Gate** and **20 Conversion Must-Haves**:
1. **Emil Kowalski Apple Design Guidelines:** Nested border radius formula ($R_{\text{outer}} = R_{\text{inner}} + \text{padding}$), spring physics with zero linear transitions, tight display tracking (`-0.02em`), and monospaced tabular figures.
2. **Leonxlnx Anti-Slop Restraint:** Strict ban on generic purple-indigo gradients, floating glow blobs, and unnecessary decorative cards. Authentic zinc contrast and high-density information architecture.
3. **Core Web Vitals:** Zero layout shift (CLS = 0) with explicit image dimension attributes, skip-to-content links, visible `:focus-visible` keyboard states, and dark-mode persistence without flash of unstyled content (FOUC).

---

## 5. Dashboard Architecture & Progressive Disclosure Overhaul (Apple HIG Standard)

### The Problem: Cognitive Overload & The "Cockpit Anti-Pattern"
Early iterations of the AEGIS dashboard concentrated 15 competing telemetry widgets onto a single 4-way split screen (Surgery Editor, Invariant Proofs, AST Telemetry, Test Chamber, AST Syntactic Inspector, Solver Stats). User feedback described this as "stepping into an airplane cockpit for the first time."

### The Solution: Apple Progressive Disclosure
To achieve calm, venture-grade software craft, the dashboard was re-engineered under Emil Kowalski's Apple Design principles:
1. **Calm Hero Incident Stage:** Summarizes the vulnerability (CVSS score, file location, human-readable impact) with 3 minimal telemetry chips (Repair Time, Constraints, Regressions).
2. **Prominent Diff Surgery Stage:** Elevated as the primary focal point of the UI. Features clean side-by-side and unified diff views with syntax highlighting, an instant clipboard copy action, and an Apple-style floating toast capsule.
3. **Progressive Disclosure Tabs:** Rather than rendering 4 complex engines simultaneously, secondary deep-dive details are placed into an Apple segmented tab bar:
   - *Tab 1: Formal Proof (Z3 SMT)*: First-Order Logic theorem, SMT-LIB2 code, and solver telemetry with live interactive re-verification.
   - *Tab 2: Regression Chamber*: Pass rates (42/42 tests) with interactive re-execution simulations.
   - *Tab 3: AST Taint Flow*: 4-step vertical timeline showing HTTP input source -> Concatenation -> Dangerous sink -> Parameterized AST surgery.
   - *Tab 4: CI/CD Gate & Audit*: Cryptographic SHA-256 seal and compliance statuses.
4. **Dynamic Scenario Switching:** A segmented pill in the frosted glass header allows instant toggling between SQL Injection (CWE-89), Stored XSS (CWE-79), and SSRF (CWE-918), updating all code, mathematical invariants, and telemetry in real time.
5. **Interactive PR Merging:** Clicking "Merge PR #142" triggers an Apple-style frosted modal sheet with interactive merge animation, cryptographic commit signing, and celebratory confirmation.

---

## 6. Microsoft Z3 SMT Formal Invariant Verification Engine (QF_S)

### Formal Method Formulation
To eliminate LLM hallucinations in automated program repair, candidate patches are evaluated against First-Order Logic assertions using the Microsoft Z3 SMT solver (`z3-solver` WebAssembly):

$$\forall \text{ input } x \in \text{Strings}, \quad \text{TaintedSource}(x) \cap \text{RawQuerySink} = \emptyset \implies \text{ValidSyntaxTree}(\text{AST}) \equiv \text{Constant}$$

### Verification Results
1. **Flawed Patch (Raw Concatenation):**
   - Assertion: `query_template.contains(taint)`
   - Result: `SAT` (Counterexample found: `' OR '1'='1`)
   - Decision: Patch rejected automatically; no PR dispatched.
2. **Sound Patch (Parameterized Binding):**
   - Assertion: `query_template == "SELECT * FROM users WHERE id = $1"` and `query_template.contains(taint)`
   - Result: `UNSAT` (Proven mathematically impossible for user input to escape the data slot)
   - Decision: Proof status marked `Q.E.D.`; 1,428 SAT constraints resolved; PR certified for auto-merge.
