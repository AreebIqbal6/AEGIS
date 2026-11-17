# AEGIS Frontend Master Specification & Claude Prompt
*Comprehensive Architecture, Module Breakdown, Interaction Graph, and Design Directive for Claude*

---

## Part 1: Ready-to-Paste Prompt for Claude

```markdown
You are an elite Staff Frontend & Design Engineer tasked with creating the production web frontend for **AEGIS (Automated Vulnerability-Patch Assistant for CI/CD Pipelines)**.

Read the specifications, module breakdowns, data flows, and constraints below. Then, use your own brain, design taste, and creativity to craft a world-class, high-craft developer tool interface (inspired by the craft of Linear, Apple Developer tools, Vercel, and Raycast).

### 🚨 Critical Scope & Honesty Boundaries (from AGENTS.md — Non-Negotiable)
AEGIS is an academic and production CI/CD security tool (Final Year Project). Correctness, authenticity, and transparency matter more than a flashy demo. You MUST follow these boundaries:
1. **Zero Silent Mock Data:** Every metric, status, count, and claim rendered on screen MUST carry a visible provenance tag:
   - `[live]`: Values that come from the real engine, database, or test runner.
   - `[seed/demo data]`: Scenarios or data staged for roadmap demonstration.
   - `[not implemented]`: Features that are not yet wired to a live solver/engine.
2. **No Fake Formal Verification:** Do NOT claim mathematical proof ("Q.E.D.", "Z3 SAT", "Formal Proof Certified") unless a real solver actually ran and produced output. For formal solver claims, label them honestly as `Formal Proof: Not Implemented [not implemented]` or Roadmap Specification.
3. **No Autonomous Hot-Patching or Auto-Merge:** AEGIS does NOT patch running processes in memory and does NOT merge its own PRs. Every fix creates a real GitHub Pull Request for a human maintainer to review and merge manually. Auto-merge is strictly `DISABLED [policy]`.
4. **Real Measured Timings:** Never invent arbitrary numbers like "44.4ms" or "1,428 constraints". Use real measured numbers from the pipeline:
   - `158.5 ms` (measured `node --test` runner latency)
   - `sample-app/src/auth.ts:15` (real vulnerable code target)
   - `4 / 4 passed (100%)` (3 functional auth tests + 1 adversarial injection test)
   - `Pull Request #1` (Live on GitHub: https://github.com/AreebIqbal6/AEGIS/pull/1)

---

### 🏛️ What AEGIS Actually Is
AEGIS is an automated security pipeline that:
1. **Finds** vulnerabilities in source code using **Tree-sitter AST** pattern matching (currently detecting CWE-89 SQL Injection in TypeScript).
2. **Drafts** an automated fix by synthesizing an AST code transformation into safe parameterized queries.
3. **Verifies** the patch by running the actual test suite (`node --test`), plus an adversarial exploit payload (`' OR '1'='1`) to confirm the exploit is blocked.
4. **Opens** a real GitHub Pull Request with the diff and test output attached for human review.

---

### 🧩 Complete Module & Sub-Module Architecture

#### 1. Header & Primary Navigation Bar
- **Brand Emblem:** AEGIS logo (`logo-cutout.png` or SVG) + version pill (`v1.0 AST Engine` or `CI/CD Patch Assistant`).
- **Target Repository Context:** Displays `AreebIqbal6/AEGIS` linking to GitHub + active PR badge: `PR #1: Open [live]`.
- **Global Search / Command Palette Trigger:** `⌘K` or `Ctrl+K` trigger opening the command palette.
- **Data Ledger Button:** Direct access to `DATA_LEDGER.md` audit modal showing 100% provenance of every number.
- **SQLite Database Status Pill:** Shows connection state to `sample-app/data/app.db` or `data/aegis.db` with live table row count.
- **Live PR Action Button:** Prominent call-to-action button: `Review PR #1 on GitHub` linking directly to `https://github.com/AreebIqbal6/AEGIS/pull/1`. No fake merge buttons!

#### 2. Sub-Nav & Scenario Switcher
- **Breadcrumb Navigation:** `pipeline / sample-app / CWE-89: SQL Injection`.
- **Scenario Tabs (with explicit provenance badges):**
  - **CWE-89: SQLi `[LIVE]`:** Real active pipeline on `sample-app/src/auth.ts:15`.
  - **CWE-79: XSS `[SEED DEMO]`:** DOM XSS scenario illustrating future engine extension.
  - **CWE-918: SSRF `[SEED DEMO]`:** Server-Side Request Forgery scenario illustrating future engine extension.
- When switching to non-live scenarios, an alert banner immediately clarifies that the scenario contains seed demo data and only CWE-89 is currently wired to the live Tree-sitter pipeline.

#### 3. Incident Hero & Provenance Telemetry Bar
- **Severity Badge:** `CRITICAL SEVERITY (CVSS 9.8) [live]` (clickable to open CVSS breakdown modal).
- **Target File Badge:** `sample-app/src/auth.ts:15 [live]`.
- **Test Status Badge:** `Sandboxed Tests: 4/4 Passed [live]`.
- **Formal Solver Badge:** `Formal Proof: Not Implemented [not implemented]`.
- **SQLite Badge:** `sample-app/data/app.db [live]`.
- **Hero Title & Narrative:** Plain-language, rigorous explanation of the vulnerability, AST taint path, and verified fix.
- **3 KPI Telemetry Cards (Real Measured Values):**
  1. *Test Runner Latency:* `158.5 ms [live]` (subshell execution timer).
  2. *AST Detection Offset:* `Line 15:15 [live]` (Tree-sitter CST traversal).
  3. *Test Suite Pass Rate:* `4 / 4 (100%) [live]` (Adversarial exploit defused).

#### 4. Surgery Editor & AST Code Diff Canvas
- **Diff Toolbar:**
  - File path chip: `sample-app/src/auth.ts` (+2 / -2 lines).
  - Mode toggle: **Side-by-Side** vs. **Unified Diff**.
  - **Copy Patch** button (copies git unified diff to clipboard with feedback).
  - **Download .patch** button (downloads `AEGIS-CWE89.patch`).
- **Before Code (Vulnerable Concatenation) `[live]`:**
  ```typescript
  export function findUserById(userId: string): User | undefined {
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    const row = db.prepare(query).get() as User | undefined;
    return row;
  }
  ```
  *Hazard Callout:* Explains how untrusted `userId` escapes SQL tokenizer boundaries.
- **After Code (AEGIS Parameterized Patch) `[live]`:**
  ```typescript
  export function findUserById(userId: string): User | undefined {
    const query = "SELECT * FROM users WHERE id = ?";
    const row = db.prepare(query).get(userId) as User | undefined;
    return row;
  }
  ```
  *Safe Anchor Callout:* Explains parameter binding slot `?` treating user input as literal data.
- **Unified Diff View:** Real diff generated by the `diff` library.
- **AST Syntactic Pattern Inspector:**
  - Identifier Sink: `db.prepare()` `[live]`
  - Taint Origin: `param: userId` `[live]`
  - Syntactic Rewrite: `BinaryConcat → Parameterized Call` `[live]`
  - Verification State: `4/4 Tests Pass` `[live]`

#### 5. Live Pipeline Execution Logs Console
- Collapsible or docked terminal streaming real pipeline step logs (Step 1 through Step 5):
  - `[STEP 1]` Target sample app validated.
  - `[STEP 2]` Tree-sitter matched CST node at `sample-app/src/auth.ts:15:15`.
  - `[STEP 3]` PatchGenerator synthesized parameterized AST diff.
  - `[STEP 4]` TestVerifier ran `node --test`: 4 passed, 0 failed in 158.5ms.
  - `[STEP 5]` GitHub PR #1 opened on branch `aegis/fix-cwe89-sqli-mwkgsz0j`.
- Actions: Clear logs, pause stream, copy logs.

#### 6. Right Column: Verification Chamber & PR Hub
- **Sandboxed Test Suite Card:**
  - Displays all 4 real tests from `sample-app/test/auth.test.ts`:
    1. `✔ should authenticate valid user alice_admin with id user_admin (1.16ms)` `[live]`
    2. `✔ should authenticate valid user bob_user with id user_bob (0.29ms)` `[live]`
    3. `✔ should return undefined for nonexistent user_ghost (0.23ms)` `[live]`
    4. `✔ should prevent SQL injection bypass using payload: ' OR '1'='1 (0.23ms)` `[live]`
  - Interactive "Re-Run node --test Suite" button with real execution feedback.
- **GitHub Pull Request Card:**
  - Title: `fix(security): parameterize SQL query in auth.ts [CWE-89]`
  - PR Number: `#1` (State: `OPEN [live]`)
  - Branch: `aegis/fix-cwe89-sqli-mwkgsz0j` -> `main`
  - Auto-Merge Policy Notice: Explicitly explains that AEGIS never auto-merges; human maintainer review is required.
  - Direct Button: `Inspect Pull Request #1 on GitHub` (opens `https://github.com/AreebIqbal6/AEGIS/pull/1`).
- **Adversarial Exploit Sandbox Card:**
  - Interactive payload tester with preset `' OR '1'='1`.
  - Demonstrates why unpatched code evaluates `'1'='1'` to true (leaking `alice_admin`) vs. patched code treating it as literal string (returning `undefined`).
- **Formal Solver Status Card:**
  - Honestly labeled `Formal Proof: Not Implemented [not implemented]`.
  - Explains the roadmap for Microsoft Z3 SMT string theory integration in Phase 2.
  - Button to view SMT-LIB2 constraint model.

#### 7. Modals & Secondary Screens
1. **Data Ledger Modal (`DATA_LEDGER.md`):** Complete searchable/filterable table documenting every displayed metric, value, provenance tag, and actual verification mechanism.
2. **SQLite Database Studio Modal:**
   - Table viewer for SQLite tables (`users`, `scans`, `vulnerabilities`, `formal_proofs`, `patches`, `test_cases`, `pr_audit_logs`).
   - Interactive SQL query runner with execution latency and JSON export.
3. **Adversarial Exploit Simulator Modal:** Interactive tester comparing unpatched vs. patched tokenizer execution.
4. **SMT-LIB2 Logic Specification Modal:** Displays the First-Order Logic QF_S constraint script clearly labeled as Phase 2 Roadmap Specification.
5. **CVSS v3.1 Calculator / Vector Modal:** Shows `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` score breakdown.
6. **Command Palette (`⌘K`):** Fast navigation across scenarios, modals, and links.

---

### 🎨 Design & Craft Guidelines for Claude
Use your own aesthetic intelligence and creativity to make this look incredible:
- **Design Personality:** High-craft developer cockpit (dark mode default: deep rich slate `#06080c`, subtle borders `border-white/10`, frosted glass surfaces with `backdrop-filter: blur(20px)`).
- **Typography:** Refined font hierarchy (Inter or system sans for UI, JetBrains Mono or SF Mono for code/telemetry, tight tracking `-0.02em` on titles).
- **Interactions:** Apple spring curves (`cubic-bezier(0.16, 1, 0.3, 1)`), subtle tactile button presses (`scale(0.98)`), micro-toasts for copy actions.
- **Accessibility & Anti-Slop:**
  - Semantic HTML (`<header>`, `<nav>`, `<main>`, `<section>`, `<footer>`).
  - Visible `:focus-visible` focus rings.
  - Skip to content link.
  - Zero placeholder text (`lorem ipsum`, `[Company]`).
  - Mobile responsiveness: must look stunning from 375px mobile viewports to 4K ultra-wide monitors.
```

---

## Part 2: Backend API Endpoints & Real Data Schema Reference

If you want Claude to connect the frontend to the local Node.js Express backend (`npm run start` or `node dist/server/server.js` on port `3456`), here are the available endpoints:

| Method | Endpoint | Description | Sample Response Payload |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Engine & DB health | `{"status":"UP","database":{"tables":[...]},"uptime":120}` |
| `GET` | `/api/vulnerabilities` | List all vulnerability bundles | `{"success":true,"count":3,"data":[...]}` |
| `GET` | `/api/vulnerabilities/:id`| Get bundle by ID | `{"success":true,"data":{"vulnerability":{...},"patch":{...}}}` |
| `GET` | `/api/scans` | Recent AST scan history | `{"success":true,"count":3,"data":[...]}` |
| `POST` | `/api/scan/file` | Run AST analysis on file | `{"filePath":"sample-app/src/auth.ts"}` |
| `POST` | `/api/tests/run` | Execute regression tests | `{"vulnerabilityId":"AEGIS-VULN-CWE89-001"}` |
| `POST` | `/api/db/query` | Execute arbitrary SQL | `{"sql":"SELECT id, username, role FROM users"}` |

---

## Part 3: Live Ground Truth Data for Claude

- **Live Pull Request:** `https://github.com/AreebIqbal6/AEGIS/pull/1`
- **GitHub Repository:** `https://github.com/AreebIqbal6/AEGIS`
- **GitHub Pages:** `https://areebiqbal6.github.io/AEGIS/`
- **Vercel Production:** `https://aegisfyp.vercel.app/`
- **Target File:** `sample-app/src/auth.ts` (Line 15, Column 15)
- **Measured Test Runner Latency:** `158.5 ms`
- **Test Runner:** Node.js native `node --test sample-app/dist/test/auth.test.js`
- **Adversarial Payload:** `' OR '1'='1` (extracts `alice_admin` before patch, returns `undefined` after patch)
