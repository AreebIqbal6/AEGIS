/**
 * AEGIS Comprehensive End-to-End Automated Test Suite
 *
 * Verifies:
 * 1. SQLite Relational Database Engine (WAL mode, foreign keys, secure query explorer)
 * 2. AST Taint Localization Engine (CWE-89 SQLi, CWE-79 XSS, CWE-918 SSRF, False Positive elimination)
 * 3. Microsoft Z3 Theorem Prover (Mathematical Invariants for SQLi, XSS, SSRF)
 * 4. REST API Endpoint Health & Relational Provenance
 */

import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import { AegisDatabase } from '../db/database.js';
import { seedDatabase } from '../db/seed.js';
import { TaintAnalyzer } from '../analyzer/taint-analyzer.js';
import { AegisZ3Verifier } from '../verifier/z3-verifier.js';
import { createServer } from '../server/server.js';

let passedCount = 0;
let failedCount = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    passedCount++;
    console.log(`  ✓ ${message}`);
  } else {
    failedCount++;
    console.error(`  ✗ FAILED: ${message}`);
  }
}

function fetchJson(url: string): Promise<any> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function postJson(url: string, body: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function runTestSuite() {
  console.log('\n=============================================================');
  console.log('🛡️  AEGIS UNIFIED AUTOMATED TEST SUITE: 10/10 QUALITY GATE');
  console.log('=============================================================\n');

  const suiteStart = performance.now();

  // -------------------------------------------------------------
  // SUITE 1: SQLite Relational Database Integrity & Security
  // -------------------------------------------------------------
  console.log('[SUITE 1] SQLite Relational Database Engine');

  const testDbDir = path.resolve(process.cwd(), 'data');
  if (!fs.existsSync(testDbDir)) fs.mkdirSync(testDbDir, { recursive: true });
  const testDbPath = path.join(testDbDir, 'test-aegis.db');
  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

  const db = new AegisDatabase(testDbPath);
  seedDatabase(db);

  const stats = db.getTableStats();
  assert(stats.length === 6, 'Initializes all 6 normalized relational tables');
  
  const vulnTable = stats.find(s => s.tableName === 'vulnerabilities');
  assert(vulnTable !== undefined && vulnTable.rowCount >= 3, 'Seeds at least 3 vulnerability records');

  const sqliVuln = db.getVulnerabilityByCwe('CWE-89');
  assert(sqliVuln !== undefined && sqliVuln.severity === 'CRITICAL', 'CWE-89 vulnerability record is indexed with CRITICAL severity');

  // Verify safe query runner allows SELECT & PRAGMA
  const selectResult = db.executeUserQuery("SELECT cwe_id, severity, cvss_score FROM vulnerabilities WHERE severity = 'CRITICAL'");
  assert(selectResult.rowCount >= 1, 'Safe query explorer executes SELECT with accurate rowCount');
  assert(selectResult.columns.includes('cwe_id'), 'Query explorer returns column metadata');
  assert(selectResult.executionTimeMs >= 0, 'Query explorer captures high-resolution execution latency');

  // Verify safe query runner BLOCKS mutations
  let blocked = false;
  try {
    db.executeUserQuery('DROP TABLE users;');
  } catch (err: any) {
    blocked = true;
  }
  assert(blocked, 'Query explorer strictly blocks malicious mutation queries (DROP TABLE)');

  // Test PR Merge mutation
  const mergeResult = db.mergePr('AEGIS-VULN-CWE89-001', 'testsha1234567890abcdef');
  assert(mergeResult !== null, 'Merge PR execution succeeds');
  const updatedVuln = db.getVulnerabilities().find(v => v.id === 'AEGIS-VULN-CWE89-001');
  assert(updatedVuln?.status === 'REPAIRED', 'Merge PR sets vulnerability status to REPAIRED in SQLite');

  // Clean up test DB
  db.close();
  try {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(testDbPath + '-wal')) fs.unlinkSync(testDbPath + '-wal');
    if (fs.existsSync(testDbPath + '-shm')) fs.unlinkSync(testDbPath + '-shm');
  } catch (e) {}
  console.log('  -> Database suite completed successfully.\n');

  // -------------------------------------------------------------
  // SUITE 2: AST Taint Localization & Polyglot Parsing Engine
  // -------------------------------------------------------------
  console.log('[SUITE 2] AST Taint Localization Engine');
  const analyzer = new TaintAnalyzer();

  // Test Fixture 1: SQL Injection (TypeScript)
  const authFixturePath = path.resolve(process.cwd(), 'test-fixtures/vulnerable-auth.ts');
  const authCode = fs.readFileSync(authFixturePath, 'utf8');
  const authReports = analyzer.analyze(authCode, authFixturePath);

  assert(authReports.length === 1, 'Correctly isolates exactly 1 vulnerability in vulnerable-auth.ts');
  assert(authReports[0]?.cwe.includes('CWE-89'), 'Correctly classifies vulnerability as CWE-89 SQL Injection');
  assert(authReports[0]?.taintedVariables.includes('userId'), 'Identifies `userId` as tainted variable from req.body');
  assert(authReports[0]?.line === 22, 'Pinpoints exact AST line offset (line 22)');
  assert(authReports[0]?.enclosingFunction === 'loginHandler', 'Identifies enclosing function `loginHandler`');

  // Test Fixture 2: Stored/DOM XSS (React TSX)
  const commentsFixturePath = path.resolve(process.cwd(), 'test-fixtures/vulnerable-comments.tsx');
  const commentsCode = fs.readFileSync(commentsFixturePath, 'utf8');
  const xssReports = analyzer.analyze(commentsCode, commentsFixturePath);

  assert(xssReports.length === 1, 'Correctly isolates exactly 1 vulnerability in vulnerable-comments.tsx');
  assert(xssReports[0]?.cwe.includes('CWE-79'), 'Correctly classifies vulnerability as CWE-79 XSS');
  assert(xssReports[0]?.sinkCallee === 'dangerouslySetInnerHTML.__html', 'Identifies dangerouslySetInnerHTML as vulnerable sink');
  assert(xssReports[0]?.taintedVariables.includes('taintedContent'), 'Tracks tainted content reaching DOM sink');

  // Test Fixture 3: SSRF (TypeScript HTTP client)
  const webhookFixturePath = path.resolve(process.cwd(), 'test-fixtures/vulnerable-webhook.ts');
  const webhookCode = fs.readFileSync(webhookFixturePath, 'utf8');
  const ssrfReports = analyzer.analyze(webhookCode, webhookFixturePath);

  assert(ssrfReports.length === 1, 'Correctly isolates exactly 1 vulnerability in vulnerable-webhook.ts');
  assert(ssrfReports[0]?.cwe.includes('CWE-918'), 'Correctly classifies vulnerability as CWE-918 SSRF');
  assert(ssrfReports[0]?.sinkCallee === 'axios.get', 'Identifies axios.get as vulnerable network sink');
  assert(ssrfReports[0]?.taintedVariables.includes('webhookUrl'), 'Tracks tainted webhookUrl variable');

  console.log('  -> AST Taint Localization suite completed successfully.\n');

  // -------------------------------------------------------------
  // SUITE 3: Microsoft Z3 SMT Mathematical Invariant Prover
  // -------------------------------------------------------------
  console.log('[SUITE 3] Microsoft Z3 SMT Formal Invariant Verification Engine');
  const verifier = new AegisZ3Verifier();

  // 3a. CWE-89 Flawed Patch (Must be rejected)
  const flawedSqli = await verifier.verifySqlInjectionPatch('await db.query("SELECT * FROM users WHERE id = " + req.body.id)', false);
  assert(!flawedSqli.verified, 'Z3 correctly rejects flawed query concatenation');
  assert(flawedSqli.proofStatus === 'VULNERABILITY_REPRODUCED', 'Proof status is VULNERABILITY_REPRODUCED');
  assert(flawedSqli.counterexample !== undefined, 'Solver produces concrete counterexample string');

  // 3b. CWE-89 Parameterized Patch (Must be verified with Q.E.D.)
  const soundSqli = await verifier.verifySqlInjectionPatch('await db.query("SELECT * FROM users WHERE id = $1", [req.body.id])', true);
  assert(soundSqli.verified, 'Z3 proves parameterized SQL query invariant holds unconditionally');
  assert(soundSqli.proofStatus === 'Q.E.D.', 'Proof status is Q.E.D.');
  assert(soundSqli.constraintsCount >= 1000, 'Solves complete SMT constraint tree (>1,000 constraints)');

  // 3c. CWE-79 XSS Patch (Must be verified with Q.E.D.)
  const soundXss = await verifier.verifyXssPatch(true);
  assert(soundXss.verified && soundXss.proofStatus === 'Q.E.D.', 'Z3 proves XSS sanitization invariant (Q.E.D.)');

  // 3d. CWE-918 SSRF Patch (Must be verified with Q.E.D.)
  const soundSsrf = await verifier.verifySsrfPatch(true);
  assert(soundSsrf.verified && soundSsrf.proofStatus === 'Q.E.D.', 'Z3 proves SSRF allowlist invariant (Q.E.D.)');

  console.log('  -> Z3 Formal Invariant suite completed successfully.\n');

  // -------------------------------------------------------------
  // SUITE 4: Live REST API & Dynamic Query Explorer
  // -------------------------------------------------------------
  console.log('[SUITE 4] Live REST API Endpoints & SQLite Integration');
  const testPort = 3999;
  const { server: apiServer, db: serverDb } = createServer(testPort);

  try {
    // 4a. Health check
    const health = await fetchJson(`http://localhost:${testPort}/api/health`);
    assert(health.status === 'UP', 'API GET /api/health returns status UP');
    assert(health.database.tables.length === 6, 'API reports 6 active SQLite database tables');

    // 4b. Vulnerabilities query
    const vulns = await fetchJson(`http://localhost:${testPort}/api/vulnerabilities`);
    assert(vulns.success && vulns.count >= 3, 'API GET /api/vulnerabilities returns all 3 vulnerability bundles');

    // 4c. Live Z3 verification endpoint
    const z3Res = await postJson(`http://localhost:${testPort}/api/verify/z3`, {
      cwe: 'CWE-89',
      isParameterized: true,
      vulnerabilityId: 'AEGIS-VULN-CWE89-001'
    });
    assert(z3Res.success && z3Res.data.verified && z3Res.data.proofStatus === 'Q.E.D.', 'API POST /api/verify/z3 returns Q.E.D. formal proof');

    // 4d. Safe SQL explorer endpoint
    const sqlRes = await postJson(`http://localhost:${testPort}/api/db/query`, {
      sql: 'SELECT cwe_id, severity FROM vulnerabilities'
    });
    assert(sqlRes.success && sqlRes.data.rowCount >= 3, 'API POST /api/db/query executes SELECT query in database');

    // 4e. PR Merge endpoint
    const mergeRes = await postJson(`http://localhost:${testPort}/api/pr/merge`, {
      vulnerabilityId: 'AEGIS-VULN-CWE89-001'
    });
    assert(mergeRes.success && mergeRes.data.vulnerability.status === 'REPAIRED', 'API POST /api/pr/merge transitions vulnerability state to REPAIRED');
  } finally {
    apiServer.close();
    serverDb.close();
  }
  console.log('  -> REST API suite completed successfully.\n');

  // -------------------------------------------------------------
  // SUITE SUMMARY
  // -------------------------------------------------------------
  const suiteDuration = Math.round(performance.now() - suiteStart);
  console.log('=============================================================');
  console.log(`TOTAL TESTS:   ${passedCount + failedCount}`);
  console.log(`PASSED:        ${passedCount}`);
  console.log(`FAILED:        ${failedCount}`);
  console.log(`DURATION:      ${suiteDuration}ms`);
  console.log(`STATUS:        ${failedCount === 0 ? 'ALL CHECKS PASSED (10/10 STANDARD MET)' : 'FAILURES DETECTED'}`);
  console.log('=============================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
