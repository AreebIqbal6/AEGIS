# Memory Bank: Technical Context
<!-- Tech Stack, Libraries, Runtime Versions, and Tooling Ecosystem -->

## Core Technologies
* **Runtime & Primary Language:** TypeScript / Node.js (v20+ LTS) & Rust (for high-throughput AST traversal and SMT bindings).
* **AST Parsing & Grammar:** Tree-sitter (`tree-sitter`, `tree-sitter-typescript`, `tree-sitter-python`).
* **Formal Verification Engine:** Microsoft Z3 SMT Solver (`z3-solver` Node/WASM bindings and native binary).
* **Neural Synthesis Models:**
  * *Local Offline Mode:* Ollama running `qwen2.5-coder:7b` / `deepseek-coder:6.7b`.
  * *Cloud / Enterprise Mode:* Anthropic Claude 3.5 Sonnet / Gemini 2.0 Flash via Vercel AI SDK.
* **Test Runner & Sandboxing:** Vitest (`vitest/node`), `isolated-vm`, Docker Engine API.
* **Frontend Cockpit:** Next.js 14+ (App Router), Tailwind CSS, shadcn/ui, React Three Fiber (R3F), React Flow, Lucide React, JetBrains Mono & Geist fonts.
* **Security & SAST Tooling Integration:** Semgrep, Gitleaks, OWASP ZAP, Snyk benchmarks.
