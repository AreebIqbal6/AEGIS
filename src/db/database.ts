import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';

export interface ScanRecord {
  id: string;
  target_file: string;
  status: string;
  vulnerabilities_count: number;
  execution_time_ms: number;
  created_at: string;
}

export interface VulnerabilityRecord {
  id: string;
  scan_id: string;
  cwe_id: string;
  cwe_title: string;
  severity: string;
  cvss_score: number;
  cvss_vector: string;
  file_path: string;
  line_number: number;
  column_number: number;
  enclosing_function: string;
  tainted_variable: string;
  sink_callee: string;
  raw_code_snippet: string;
  description: string;
  status: string;
}

export interface PatchRecord {
  id: string;
  vulnerability_id: string;
  strategy: string;
  before_code: string;
  after_code: string;
  diff_content: string;
  unified_diff: string;
  is_parameterized: number;
}

export interface FormalProofRecord {
  id: string;
  vulnerability_id: string;
  patch_id: string;
  first_order_formula: string;
  smt_lib2_code: string;
  solver_engine: string;
  solver_status: string;
  is_verified: number;
  solver_time_ms: number;
  constraints_count: number;
  counterexample?: string;
  inductive_step: string;
  verified_at: string;
}

export interface TestCaseRecord {
  id: string;
  vulnerability_id: string;
  test_name: string;
  is_security_test: number;
  execution_time_ms: number;
  status: string;
}

export interface PrAuditRecord {
  id: string;
  vulnerability_id: string;
  pr_number: number;
  source_branch: string;
  target_branch: string;
  commit_sha: string;
  gpg_key_id: string;
  merged_by: string;
  merged_at: string;
  status: string;
}

export class AegisDatabase {
  private db: Database.Database;
  private dbPath: string;

  constructor(customPath?: string) {
    const dataDir = path.resolve(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    this.dbPath = customPath || path.join(dataDir, 'aegis.db');
    this.db = new Database(this.dbPath);
    this.init();
  }

  public getDatabasePath(): string {
    return this.dbPath;
  }

  private init() {
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target_file TEXT NOT NULL,
        status TEXT NOT NULL,
        vulnerabilities_count INTEGER DEFAULT 0,
        execution_time_ms REAL NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
        cwe_id TEXT NOT NULL,
        cwe_title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        cvss_vector TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_number INTEGER NOT NULL,
        column_number INTEGER NOT NULL,
        enclosing_function TEXT NOT NULL,
        tainted_variable TEXT NOT NULL,
        sink_callee TEXT NOT NULL,
        raw_code_snippet TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'DETECTED'
      );

      CREATE TABLE IF NOT EXISTS patches (
        id TEXT PRIMARY KEY,
        vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        strategy TEXT NOT NULL,
        before_code TEXT NOT NULL,
        after_code TEXT NOT NULL,
        diff_content TEXT NOT NULL,
        unified_diff TEXT NOT NULL,
        is_parameterized INTEGER NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS formal_proofs (
        id TEXT PRIMARY KEY,
        vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        patch_id TEXT REFERENCES patches(id) ON DELETE CASCADE,
        first_order_formula TEXT NOT NULL,
        smt_lib2_code TEXT NOT NULL,
        solver_engine TEXT NOT NULL,
        solver_status TEXT NOT NULL,
        is_verified INTEGER NOT NULL,
        solver_time_ms REAL NOT NULL,
        constraints_count INTEGER NOT NULL,
        counterexample TEXT,
        inductive_step TEXT NOT NULL,
        verified_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS test_cases (
        id TEXT PRIMARY KEY,
        vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        test_name TEXT NOT NULL,
        is_security_test INTEGER NOT NULL DEFAULT 0,
        execution_time_ms REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'PASSED'
      );

      CREATE TABLE IF NOT EXISTS pr_audit_logs (
        id TEXT PRIMARY KEY,
        vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        pr_number INTEGER NOT NULL,
        source_branch TEXT NOT NULL,
        target_branch TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        gpg_key_id TEXT NOT NULL,
        merged_by TEXT NOT NULL,
        merged_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN'
      );
    `);
  }

  // --- QUERIES ---

  public getScans(): ScanRecord[] {
    return this.db.prepare('SELECT * FROM scans ORDER BY created_at DESC').all() as ScanRecord[];
  }

  public getVulnerabilities(): VulnerabilityRecord[] {
    return this.db.prepare('SELECT * FROM vulnerabilities ORDER BY cvss_score DESC').all() as VulnerabilityRecord[];
  }

  public getVulnerabilityByCwe(cweId: string): VulnerabilityRecord | undefined {
    return this.db.prepare('SELECT * FROM vulnerabilities WHERE cwe_id = ?').get(cweId) as VulnerabilityRecord | undefined;
  }

  public getVulnerabilityDetails(vulnId: string) {
    const vuln = this.db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId) as VulnerabilityRecord | undefined;
    if (!vuln) return null;

    const patch = this.db.prepare('SELECT * FROM patches WHERE vulnerability_id = ?').get(vulnId) as PatchRecord | undefined;
    const proof = this.db.prepare('SELECT * FROM formal_proofs WHERE vulnerability_id = ?').get(vulnId) as FormalProofRecord | undefined;
    const tests = this.db.prepare('SELECT * FROM test_cases WHERE vulnerability_id = ?').all(vulnId) as TestCaseRecord[];
    const pr = this.db.prepare('SELECT * FROM pr_audit_logs WHERE vulnerability_id = ?').get(vulnId) as PrAuditRecord | undefined;

    return {
      vulnerability: vuln,
      patch,
      proof,
      tests,
      pr
    };
  }

  public getAllVulnerabilityBundles() {
    const vulns = this.getVulnerabilities();
    return vulns.map(v => this.getVulnerabilityDetails(v.id));
  }

  // --- MUTATIONS ---

  public insertScan(scan: ScanRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO scans (id, target_file, status, vulnerabilities_count, execution_time_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(scan.id, scan.target_file, scan.status, scan.vulnerabilities_count, scan.execution_time_ms, scan.created_at);
  }

  public insertVulnerability(vuln: VulnerabilityRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (
        id, scan_id, cwe_id, cwe_title, severity, cvss_score, cvss_vector,
        file_path, line_number, column_number, enclosing_function,
        tainted_variable, sink_callee, raw_code_snippet, description, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      vuln.id, vuln.scan_id, vuln.cwe_id, vuln.cwe_title, vuln.severity, vuln.cvss_score, vuln.cvss_vector,
      vuln.file_path, vuln.line_number, vuln.column_number, vuln.enclosing_function,
      vuln.tainted_variable, vuln.sink_callee, vuln.raw_code_snippet, vuln.description, vuln.status
    );
  }

  public insertPatch(patch: PatchRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO patches (id, vulnerability_id, strategy, before_code, after_code, diff_content, unified_diff, is_parameterized)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(patch.id, patch.vulnerability_id, patch.strategy, patch.before_code, patch.after_code, patch.diff_content, patch.unified_diff, patch.is_parameterized);
  }

  public insertFormalProof(proof: FormalProofRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO formal_proofs (
        id, vulnerability_id, patch_id, first_order_formula, smt_lib2_code,
        solver_engine, solver_status, is_verified, solver_time_ms, constraints_count,
        counterexample, inductive_step, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      proof.id, proof.vulnerability_id, proof.patch_id, proof.first_order_formula, proof.smt_lib2_code,
      proof.solver_engine, proof.solver_status, proof.is_verified, proof.solver_time_ms, proof.constraints_count,
      proof.counterexample || null, proof.inductive_step, proof.verified_at
    );
  }

  public insertTestCase(test: TestCaseRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO test_cases (id, vulnerability_id, test_name, is_security_test, execution_time_ms, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(test.id, test.vulnerability_id, test.test_name, test.is_security_test, test.execution_time_ms, test.status);
  }

  public insertPrAudit(pr: PrAuditRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO pr_audit_logs (id, vulnerability_id, pr_number, source_branch, target_branch, commit_sha, gpg_key_id, merged_by, merged_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(pr.id, pr.vulnerability_id, pr.pr_number, pr.source_branch, pr.target_branch, pr.commit_sha, pr.gpg_key_id, pr.merged_by, pr.merged_at, pr.status);
  }

  public mergePr(vulnerabilityId: string, commitSha: string) {
    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE pr_audit_logs 
      SET status = 'MERGED', commit_sha = ?, merged_at = ?
      WHERE vulnerability_id = ?
    `).run(commitSha, now, vulnerabilityId);

    this.db.prepare(`
      UPDATE vulnerabilities
      SET status = 'REPAIRED'
      WHERE id = ?
    `).run(vulnerabilityId);

    return this.getVulnerabilityDetails(vulnerabilityId);
  }

  public executeUserQuery(sql: string): { columns: string[]; rows: any[]; rowCount: number; executionTimeMs: number } {
    const start = performance.now();
    // Only allow SELECT for safety in user query explorer
    const trimmed = sql.trim();
    if (!trimmed.toLowerCase().startsWith('select') && !trimmed.toLowerCase().startsWith('pragma')) {
      throw new Error('Database Explorer only allows read queries (SELECT / PRAGMA) for safety.');
    }

    const rows = this.db.prepare(trimmed).all();
    const duration = Math.round((performance.now() - start) * 100) / 100;
    const columns = rows.length > 0 ? Object.keys(rows[0] as object) : [];

    return {
      columns,
      rows,
      rowCount: rows.length,
      executionTimeMs: duration
    };
  }

  public getTableStats(): { tableName: string; rowCount: number }[] {
    const tables = ['scans', 'vulnerabilities', 'patches', 'formal_proofs', 'test_cases', 'pr_audit_logs'];
    return tables.map(name => {
      const count = (this.db.prepare(`SELECT COUNT(*) as count FROM ${name}`).get() as any).count;
      return { tableName: name, rowCount: count };
    });
  }
}
