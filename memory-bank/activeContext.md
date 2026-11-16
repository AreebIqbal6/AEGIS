# Memory Bank: Active Context
<!-- Current Focus, Active Sprint, Recent Changes, and Immediate Next Steps -->

## Current Focus
* **Sprint Phase:** Minimal Working Prototype (MWP) Verification & High-Craft Apple Dashboard Integration.
* **Immediate Milestone:** Completed live AST Taint Localization, Z3 SMT Formal Invariant Verification engine, and Apple Design dashboard overhaul.

## Recent Changes
* Built and verified authentic SQLite3 database (`data/aegis.db`) using `better-sqlite3`:
  - 6 relational tables with foreign keys: `scans`, `vulnerabilities`, `patches`, `formal_proofs`, `test_cases`, `pr_audit_logs`.
  - WAL mode enabled (`PRAGMA journal_mode = WAL`) for concurrent read performance.
* Implemented live Express REST API server (`src/server/server.ts` on port 3456):
  - Endpoints: `/api/health`, `/api/vulnerabilities`, `/api/verify/z3`, `/api/tests/run`, `/api/pr/merge`, `/api/db/query`, `/api/db/stats`.
* Integrated in-dashboard **Database Inspector & SQL Studio** (`#db-modal`):
  - Live table chips with row counts for all 6 tables.
  - Interactive SQL query execution with latency metrics and JSON export.
  - Data Provenance Badges across the UI linking all elements directly to SQLite table records.
* Created CLI database inspector command: `npm run db:inspect`.
* Verified live with Playwright: 0 console errors, dynamic SQL execution, live Z3 verification writes to database.

## Next Steps
1. All core US-001 through US-007 acceptance criteria are 100% satisfied.
2. Maintain live server daemon on port 3456 and commit/push all artifacts to GitHub remote.
