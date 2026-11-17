# AEGIS — Agent Rules

AEGIS is a CI/CD security tool: it finds a specific, well-defined class of
vulnerability, drafts a fix, runs real tests against it, and opens a pull
request for a human to review. It does NOT patch running processes in
memory, does NOT merge its own code, and does NOT claim mathematical proof
unless a real solver actually ran.

## Hard scope boundaries — do not build these without being asked again
- No autonomous hot-patching of a live/running process. Every fix becomes a
  PR. A human merges it. No exceptions, no "zero-downtime" shortcuts.
- No claims of formal verification (Z3, SMT, "Q.E.D.") unless the solver is
  actually invoked in code and its real output is shown. Until it's wired
  up, the UI must say "formal proof: not implemented" — not fake a result.
- No fabricated timing/precision numbers (e.g. "44.4ms", "1,428 constraints")
  unless they come from an actual measured run.

## The one rule that matters most: no silent mock data
Every number, status, or "success" state rendered anywhere MUST carry a
visible source tag: `live`, `seed/demo data`, or `not implemented`. This
applies to API calls, test results, database rows, and UI copy.
- If a fetch/API call fails or isn't wired up, the UI must say so
  explicitly ("not connected yet") — never fall back to mock data silently
  and never swallow the error while showing a success message.
- Never write a comment like "fallback to mock data" next to a UI claim
  that says the data is real. If you're not sure whether something is real
  or staged, label it staged and flag it to me instead of guessing.
- Maintain a "Data Ledger": a running list (markdown file is fine) of every
  screen/claim and its actual source. Update it in the same commit that
  adds the claim. If you add a number, add its ledger row — same commit,
  not later.

## Verification standards
- "Tests passed" means a real test runner actually ran and you're showing
  its real output. No `setTimeout` standing in for a computation.
- A "patch" must be a real, working diff against real sample code in the
  repo — not a hardcoded string in a JS object pretending to be a diff.

## Stack
- TypeScript / Node.js
- tree-sitter for AST parsing (not Babel unless tree-sitter can't cover a case)
- SQLite for storage, accessed through a real backend — no client-side
  JS object standing in for a database
- GitHub REST/GraphQL API for opening PRs — no fake merge buttons

## When in doubt
Stop and ask me, in plain language, rather than shipping a plausible-looking
fake. A clearly labeled "not built yet" is always better than a convincing
simulation.
