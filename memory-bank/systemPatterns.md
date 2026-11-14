# Memory Bank: System Patterns
<!-- System Architecture, Component Relationships, and Design Decisions -->

```mermaid
flowchart TD
    PR["GitHub Pull Request / Commit"] --> Ingest["AEGIS Ingestion & Webhook Listener"]
    Ingest --> AST["Tree-sitter AST & Taint Flow Analyzer"]
    AST --> Sink{"Is Taint Path Connected to Sink?"}
    Sink -- No --> Pass["Pass CI Gate (Clean)"]
    Sink -- Yes --> Synth["Neural Patch Synthesizer (Qwen2.5-Coder / Claude)"]
    Synth --> Z3["Formal Invariant Verification (Z3 SMT Solver)"]
    Z3 -- UNSAT / Counterexample --> Synth
    Z3 -- SAT (Proven Q.E.D.) --> Sandbox["Ephemeral Sandbox (Vitest / Isolated-VM)"]
    Sandbox -- Regression Fails --> Synth
    Sandbox -- All Tests Pass --> Dispatch["Auto-PR Dispatcher & Cryptographic Stamp"]
    Dispatch --> Dashboard["AEGIS Telemetry Cockpit (R3F / Next.js)"]
```

## Key Architectural Patterns
1. **Pipeline Architecture:** Ingestion -> AST Parsing -> Taint Tracing -> Neuro-Symbolic Synthesis -> SMT Verification -> Sandboxed Regression -> Verified Dispatch.
2. **Actor / Isolation Pattern:** Sandbox execution runs within memory-isolated containers or Node isolates to prevent malicious payload execution during verification.
3. **Formal Invariant Boundary:** Every patch must be accompanied by a mathematically verifiable predicate before reaching the test execution chamber.
4. **Audit Trail Immutability:** Every verified patch records a SHA-256 cryptographic signature, SMT solver constraint count, and timestamp.
