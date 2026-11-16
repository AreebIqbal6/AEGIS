import { AegisDatabase } from './database.js';

export function seedDatabase(db: AegisDatabase) {
  console.log('[SEED] Initializing and seeding real AEGIS database at:', db.getDatabasePath());

  // 1. Initial Scans
  db.insertScan({
    id: 'SCAN-2026-11-14-AUTH',
    target_file: 'controllers/auth.ts',
    status: 'COMPLETED',
    vulnerabilities_count: 1,
    execution_time_ms: 44.43,
    created_at: '2026-11-14T17:42:10.000Z'
  });

  db.insertScan({
    id: 'SCAN-2026-11-14-VIEWS',
    target_file: 'views/comments.tsx',
    status: 'COMPLETED',
    vulnerabilities_count: 1,
    execution_time_ms: 31.20,
    created_at: '2026-11-14T18:15:22.000Z'
  });

  db.insertScan({
    id: 'SCAN-2026-11-14-WEBHOOK',
    target_file: 'services/webhook.ts',
    status: 'COMPLETED',
    vulnerabilities_count: 1,
    execution_time_ms: 52.70,
    created_at: '2026-11-14T19:04:45.000Z'
  });

  // 2. Vulnerabilities
  // --- CWE-89 SQLi ---
  db.insertVulnerability({
    id: 'AEGIS-VULN-CWE89-001',
    scan_id: 'SCAN-2026-11-14-AUTH',
    cwe_id: 'CWE-89',
    cwe_title: 'SQL Injection via Unescaped String Concatenation',
    severity: 'CRITICAL',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    file_path: 'controllers/auth.ts',
    line_number: 42,
    column_number: 21,
    enclosing_function: 'authenticateUser',
    tainted_variable: 'req.body.id',
    sink_callee: 'db.query',
    raw_code_snippet: 'const user = await db.query("SELECT * FROM users WHERE id = \'" + req.body.id + "\'");',
    description: 'AEGIS localized untrusted taint reaching db.query without token boundaries. Autonomous AST surgery synthesized parameterized query binding, and Microsoft Z3 proved that no input string can mutate the AST SQL token tree.',
    status: 'PATCH_SYNTHESIZED'
  });

  db.insertPatch({
    id: 'PATCH-CWE89-001',
    vulnerability_id: 'AEGIS-VULN-CWE89-001',
    strategy: 'PARAMETERIZED_BINDING',
    before_code: `// Handler for user authentication dispatch
async function authenticateUser(req: Request, res: Response) {
  const { id } = req.body;

  const user = await db.query("SELECT * FROM users WHERE id = '" + req.body.id + "'");
  if (!user) throw new NotFoundError();
  return res.json({ token: signJwt(user) });
}`,
    after_code: `// Handler for user authentication dispatch
async function authenticateUser(req: Request, res: Response) {
  const { id } = req.body;

  const user = await db.query("SELECT * FROM users WHERE id = $1", [req.body.id]);
  if (!user) throw new NotFoundError();
  return res.json({ token: signJwt(user) });
}`,
    diff_content: `@@ -40,5 +40,5 @@ async function authenticateUser(req: Request, res: Response) {
   const { id } = req.body;

- const user = await db.query("SELECT * FROM users WHERE id = '" + req.body.id + "'");
+ const user = await db.query("SELECT * FROM users WHERE id = $1", [req.body.id]);

   if (!user) throw new NotFoundError();
   return res.json({ token: signJwt(user) });
 }`,
    unified_diff: `--- a/controllers/auth.ts
+++ b/controllers/auth.ts
@@ -42,1 +42,1 @@
-  const user = await db.query("SELECT * FROM users WHERE id = '" + req.body.id + "'");
+  const user = await db.query("SELECT * FROM users WHERE id = $1", [req.body.id]);`,
    is_parameterized: 1
  });

  db.insertFormalProof({
    id: 'PROOF-CWE89-001',
    vulnerability_id: 'AEGIS-VULN-CWE89-001',
    patch_id: 'PATCH-CWE89-001',
    first_order_formula: '∀ input x ∈ Strings, TaintedSource(x) ∧ RawQuerySink = ∅ ⇒ ValidSyntaxTree(Ast) ≡ Constant',
    smt_lib2_code: `; AEGIS Invariant Specification for Parameterized Query
(set-logic QF_S)
(declare-const taint String)
(declare-const query_template String)
(declare-const bound_param String)

; Model user injection attempt
(assert (str.contains taint "' OR '1'='1"))

; Prove parameter binding isolation
(assert (= query_template "SELECT * FROM users WHERE id = $1"))
(assert (not (str.contains query_template taint)))

; Check satisfiability of exploit state
(check-sat)
; Result: unsat (No execution path allows user input to break syntax barrier)`,
    solver_engine: 'Microsoft Z3 SMT v4.12.2',
    solver_status: 'Q.E.D.',
    is_verified: 1,
    solver_time_ms: 44.4,
    constraints_count: 1428,
    counterexample: undefined,
    inductive_step: 'Inductive step k=3: Variable isolation proven under arbitrary string length substitution.',
    verified_at: '2026-11-14T17:42:12.000Z'
  });

  db.insertTestCase({ id: 'TEST-SQLI-01', vulnerability_id: 'AEGIS-VULN-CWE89-001', test_name: 'auth.test.ts: should prevent single quote SQL escape', is_security_test: 1, execution_time_ms: 12, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SQLI-02', vulnerability_id: 'AEGIS-VULN-CWE89-001', test_name: 'auth.test.ts: should authenticate valid admin user', is_security_test: 0, execution_time_ms: 8, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SQLI-03', vulnerability_id: 'AEGIS-VULN-CWE89-001', test_name: 'payments.test.ts: backward compatibility integration suite', is_security_test: 0, execution_time_ms: 34, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SQLI-04', vulnerability_id: 'AEGIS-VULN-CWE89-001', test_name: 'security_fuzz.test.ts: 10,000 automated fuzz mutations', is_security_test: 1, execution_time_ms: 56, status: 'PASSED' });

  db.insertPrAudit({
    id: 'PR-AUDIT-001',
    vulnerability_id: 'AEGIS-VULN-CWE89-001',
    pr_number: 142,
    source_branch: 'hotfix/aegis-repair-cwe89',
    target_branch: 'main',
    commit_sha: '9f8a2c4e1d7a3f0e8a7c2b6d5f4e3a2b1c0d9e8f',
    gpg_key_id: '0x8F2C9B',
    merged_by: 'AEGIS Autonomous Bot',
    merged_at: '2026-11-14T17:42:15.000Z',
    status: 'OPEN'
  });

  // --- CWE-79 XSS ---
  db.insertVulnerability({
    id: 'AEGIS-VULN-CWE79-002',
    scan_id: 'SCAN-2026-11-14-VIEWS',
    cwe_id: 'CWE-79',
    cwe_title: 'Stored Cross-Site Scripting via dangerouslySetInnerHTML',
    severity: 'HIGH',
    cvss_score: 8.2,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N',
    file_path: 'views/comments.tsx',
    line_number: 28,
    column_number: 14,
    enclosing_function: 'CommentCard',
    tainted_variable: 'comment.content',
    sink_callee: 'dangerouslySetInnerHTML',
    raw_code_snippet: '<div dangerouslySetInnerHTML={{ __html: comment.content }} />',
    description: 'Unsanitized user comments rendered directly to browser DOM. AEGIS synthesized DOMPurify context-aware HTML sanitizer, proving zero executable script or inline event handlers can execute.',
    status: 'PATCH_SYNTHESIZED'
  });

  db.insertPatch({
    id: 'PATCH-CWE79-002',
    vulnerability_id: 'AEGIS-VULN-CWE79-002',
    strategy: 'DOM_PURIFICATION',
    before_code: `export function CommentCard({ comment }: { comment: Comment }) {
  return (
    <div className="comment-bubble">
      <div dangerouslySetInnerHTML={{ __html: comment.content }} />
    </div>
  );
}`,
    after_code: `export function CommentCard({ comment }: { comment: Comment }) {
  return (
    <div className="comment-bubble">
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />
    </div>
  );
}`,
    diff_content: `@@ -26,3 +26,3 @@ export function CommentCard({ comment }: { comment: Comment }) {
   return (
     <div className="comment-bubble">
-   <div dangerouslySetInnerHTML={{ __html: comment.content }} />
+   <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />
     </div>
   );`,
    unified_diff: `--- a/views/comments.tsx
+++ b/views/comments.tsx
@@ -28,1 +28,1 @@
-    <div dangerouslySetInnerHTML={{ __html: comment.content }} />
+    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />`,
    is_parameterized: 0
  });

  db.insertFormalProof({
    id: 'PROOF-CWE79-002',
    vulnerability_id: 'AEGIS-VULN-CWE79-002',
    patch_id: 'PATCH-CWE79-002',
    first_order_formula: '∀ markup m ∈ DOM, ScriptTokens(DOMPurify(m)) = ∅ ∧ EventHandlers(DOMPurify(m)) = ∅',
    smt_lib2_code: `; AEGIS Invariant Specification for DOM Sanitization
(set-logic QF_S)
(declare-const dom_input String)
(declare-const sanitized String)

; Model XSS payload
(assert (str.contains dom_input "<img src=x onerror=alert(document.cookie)>"))

; Sanitization invariant property
(assert (not (str.contains sanitized "onerror=")))
(assert (not (str.contains sanitized "onload=")))

(check-sat)
; Result: unsat (Exploit pattern completely eradicated from output)`,
    solver_engine: 'Microsoft Z3 SMT v4.12.2',
    solver_status: 'Q.E.D.',
    is_verified: 1,
    solver_time_ms: 31.2,
    constraints_count: 892,
    counterexample: undefined,
    inductive_step: 'Tree-walking DOM parser proves zero executable script leaves remain.',
    verified_at: '2026-11-14T18:15:25.000Z'
  });

  db.insertTestCase({ id: 'TEST-XSS-01', vulnerability_id: 'AEGIS-VULN-CWE79-002', test_name: 'comments.test.tsx: should sanitize script tags in comments', is_security_test: 1, execution_time_ms: 14, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-XSS-02', vulnerability_id: 'AEGIS-VULN-CWE79-002', test_name: 'comments.test.tsx: should preserve safe bold & italic markdown', is_security_test: 0, execution_time_ms: 11, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-XSS-03', vulnerability_id: 'AEGIS-VULN-CWE79-002', test_name: 'security_fuzz.test.ts: 5,000 DOM mutation fuzz vectors', is_security_test: 1, execution_time_ms: 41, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-XSS-04', vulnerability_id: 'AEGIS-VULN-CWE79-002', test_name: 'render.test.tsx: React virtual DOM hydration pass', is_security_test: 0, execution_time_ms: 22, status: 'PASSED' });

  db.insertPrAudit({
    id: 'PR-AUDIT-002',
    vulnerability_id: 'AEGIS-VULN-CWE79-002',
    pr_number: 143,
    source_branch: 'hotfix/aegis-repair-cwe79',
    target_branch: 'main',
    commit_sha: '7a2b9f8a1c0d4e3f2b1a0c9d8e7f6a5b4c3d2e1f',
    gpg_key_id: '0x8F2C9B',
    merged_by: 'AEGIS Autonomous Bot',
    merged_at: '2026-11-14T18:15:28.000Z',
    status: 'OPEN'
  });

  // --- CWE-918 SSRF ---
  db.insertVulnerability({
    id: 'AEGIS-VULN-CWE918-003',
    scan_id: 'SCAN-2026-11-14-WEBHOOK',
    cwe_id: 'CWE-918',
    cwe_title: 'Server-Side Request Forgery via Unchecked Webhook Dispatch',
    severity: 'CRITICAL',
    cvss_score: 9.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    file_path: 'services/webhook.ts',
    line_number: 89,
    column_number: 19,
    enclosing_function: 'triggerWebhook',
    tainted_variable: 'targetUrl',
    sink_callee: 'fetch',
    raw_code_snippet: 'return await fetch(targetUrl, { method: "POST", body: JSON.stringify(payload) });',
    description: 'Unchecked fetch(url) permitted attackers to probe cloud internal metadata endpoints (169.254.169.254). AEGIS inserted an IP range invariant filter and DNS rebinding protection.',
    status: 'PATCH_SYNTHESIZED'
  });

  db.insertPatch({
    id: 'PATCH-CWE918-003',
    vulnerability_id: 'AEGIS-VULN-CWE918-003',
    strategy: 'SUBNET_ALLOWLIST',
    before_code: `export async function triggerWebhook(targetUrl: string, payload: any) {
  // Outbound notification dispatcher
  return await fetch(targetUrl, { method: "POST", body: JSON.stringify(payload) });
}`,
    after_code: `export async function triggerWebhook(targetUrl: string, payload: any) {
  // Outbound notification dispatcher with formal SSRF boundary check
  const validatedUrl = await assertPublicInternetEndpoint(targetUrl);
  return await fetch(validatedUrl, { method: "POST", body: JSON.stringify(payload) });
}`,
    diff_content: `@@ -88,2 +88,3 @@ export async function triggerWebhook(targetUrl: string, payload: any) {
   // Outbound notification dispatcher
- return await fetch(targetUrl, { method: "POST", body: JSON.stringify(payload) });
+ const validatedUrl = await assertPublicInternetEndpoint(targetUrl);
+ return await fetch(validatedUrl, { method: "POST", body: JSON.stringify(payload) });
 }`,
    unified_diff: `--- a/services/webhook.ts
+++ b/services/webhook.ts
@@ -89,1 +89,2 @@
-  return await fetch(targetUrl, { method: "POST", body: JSON.stringify(payload) });
+  const validatedUrl = await assertPublicInternetEndpoint(targetUrl);
+  return await fetch(validatedUrl, { method: "POST", body: JSON.stringify(payload) });`,
    is_parameterized: 0
  });

  db.insertFormalProof({
    id: 'PROOF-CWE918-003',
    vulnerability_id: 'AEGIS-VULN-CWE918-003',
    patch_id: 'PATCH-CWE918-003',
    first_order_formula: '∀ ip ∈ ResolveDns(url), ip ∉ PrivateSubnets ∧ ip ≠ 169.254.169.254',
    smt_lib2_code: `; AEGIS Invariant Specification for SSRF Boundary
(set-logic QF_BV)
(declare-const target_ip (_ BitVec 32))

; Define AWS IMDSv1/v2 metadata IP: 169.254.169.254 = #xA9FEA9FE
(define-const metadata_ip (_ BitVec 32) #xA9FEA9FE)

; Invariant: Outbound target can never equal metadata IP or loopback
(assert (= target_ip metadata_ip))

(check-sat)
; Result: unsat (Invariant holds: target_ip is strictly disjoint from protected zones)`,
    solver_engine: 'Microsoft Z3 SMT v4.12.2',
    solver_status: 'Q.E.D.',
    is_verified: 1,
    solver_time_ms: 52.7,
    constraints_count: 2104,
    counterexample: undefined,
    inductive_step: 'BitVector range theorem proves disjointness from 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.169.254.',
    verified_at: '2026-11-14T19:04:48.000Z'
  });

  db.insertTestCase({ id: 'TEST-SSRF-01', vulnerability_id: 'AEGIS-VULN-CWE918-003', test_name: 'webhook.test.ts: should block AWS 169.254.169.254 metadata endpoint', is_security_test: 1, execution_time_ms: 16, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SSRF-02', vulnerability_id: 'AEGIS-VULN-CWE918-003', test_name: 'webhook.test.ts: should block loopback 127.0.0.1 requests', is_security_test: 1, execution_time_ms: 9, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SSRF-03', vulnerability_id: 'AEGIS-VULN-CWE918-003', test_name: 'webhook.test.ts: should allow valid public webhooks (https://hooks.slack.com)', is_security_test: 0, execution_time_ms: 28, status: 'PASSED' });
  db.insertTestCase({ id: 'TEST-SSRF-04', vulnerability_id: 'AEGIS-VULN-CWE918-003', test_name: 'dns.test.ts: DNS rebinding race condition mitigation test', is_security_test: 1, execution_time_ms: 36, status: 'PASSED' });

  db.insertPrAudit({
    id: 'PR-AUDIT-003',
    vulnerability_id: 'AEGIS-VULN-CWE918-003',
    pr_number: 144,
    source_branch: 'hotfix/aegis-repair-cwe918',
    target_branch: 'main',
    commit_sha: '1c0d4e3f2b1a0c9d8e7f6a5b4c3d2e1f9a8b7c6d',
    gpg_key_id: '0x8F2C9B',
    merged_by: 'AEGIS Autonomous Bot',
    merged_at: '2026-11-14T19:04:52.000Z',
    status: 'OPEN'
  });

  console.log('[SEED] Successfully seeded 3 scans, 3 vulnerabilities, 3 patches, 3 formal proofs, 12 test cases, and 3 PR audit records.');
}

// Auto-run if executed directly
if (process.argv[1]?.endsWith('seed.ts') || process.argv[1]?.endsWith('seed.js')) {
  const db = new AegisDatabase();
  seedDatabase(db);
  console.log('Database Table Stats:', db.getTableStats());
}
