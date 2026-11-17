/**
 * AEGIS Core Type Definitions
 * Autonomous Engine for Program Vulnerability Repair & Formal Invariant Verification
 */

// ==========================================
// 1. Relational Database Records (SQLite)
// ==========================================

export interface ScanRecord {
  id: string;
  repo_name: string;
  branch: string;
  commit_hash: string;
  status: 'QUEUED' | 'ANALYZING' | 'VERIFYING' | 'PATCHED' | 'FAILED' | 'CLEAN';
  vulnerabilities_count: number;
  created_at: string;
  completed_at?: string | null;
}

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface VulnerabilityRecord {
  id: string;
  scan_id: string;
  cwe_id: string;
  cwe_name: string;
  file_path: string;
  line_number: number;
  column_number: number;
  severity: VulnerabilitySeverity;
  cvss_score: number;
  taint_source: string;
  taint_sink: string;
  vulnerable_code: string;
  description: string;
  created_at: string;
}

export interface PatchRecord {
  id: string;
  vulnerability_id: string;
  patch_diff: string;
  patched_code: string;
  strategy: 'PARAMETERIZATION' | 'HTML_ENCODING' | 'IP_ALLOWLIST' | 'INPUT_VALIDATION';
  status: 'SYNTHESIZED' | 'PROVED' | 'REJECTED' | 'APPLIED';
  created_at: string;
}

export type Z3ProofStatus = 'QED_VERIFIED' | 'COUNTEREXAMPLE_FOUND' | 'SOLVER_TIMEOUT' | 'UNKNOWN';

export interface FormalProofRecord {
  id: string;
  patch_id: string;
  formula_latex: string;
  smt_constraints_count: number;
  solver_engine: string;
  verification_status: Z3ProofStatus;
  execution_latency_ms: number;
  peak_memory_mb: number;
  counterexample?: string | null;
  created_at: string;
}

export interface TestCaseRecord {
  id: string;
  patch_id: string;
  test_file: string;
  test_name: string;
  status: 'PASSED' | 'FAILED' | 'SKIPPED';
  duration_ms: number;
  output?: string | null;
  created_at: string;
}

export interface PrAuditLogRecord {
  id: string;
  pr_number: number;
  repo_name: string;
  branch_name: string;
  commit_sha: string;
  action: 'PROPOSED' | 'CHECK_PASSED' | 'CHECK_FAILED' | 'MERGED' | 'REJECTED';
  signed_by: string;
  details?: string | null;
  timestamp: string;
}

// ==========================================
// 2. AST Taint Analysis Engine Types
// ==========================================

export interface TaintSource {
  name: string;
  type: 'HTTP_REQUEST' | 'CLI_ARG' | 'EXTERNAL_SOCKET' | 'ENV_VAR';
  scope: string;
}

export interface TaintSink {
  name: string;
  type: 'SQL_QUERY' | 'RAW_HTML' | 'HTTP_REQUEST' | 'SHELL_EXEC';
  functionCall: string;
  argumentIndex: number;
}

export interface TaintFlowStep {
  step: number;
  nodeType: string;
  identifier: string;
  line: number;
  column: number;
  codeSnippet: string;
  tainted: boolean;
}

export interface TaintReport {
  vulnerabilityId: string;
  cwe: string;
  severity: VulnerabilitySeverity;
  filePath: string;
  line: number;
  column: number;
  source: TaintSource;
  sink: TaintSink;
  flowPath: TaintFlowStep[];
  vulnerableSnippet: string;
  transformationRecommendation: string;
}

// ==========================================
// 3. Formal Invariant & Z3 Verifier Types
// ==========================================

export interface InvariantSpecification {
  cwe: string;
  formula: string;
  antecedent: string;
  consequent: string;
}

export interface Z3VerificationResult {
  status: 'SAT' | 'UNSAT' | 'UNKNOWN';
  qed: boolean;
  constraintsCount: number;
  executionLatencyMs: number;
  peakMemoryMb: number;
  solverVersion: string;
  proofState: string;
  invariantFormula: string;
  counterexample: string | null;
  details: string;
}

// ==========================================
// 4. Database & REST API Operational Types
// ==========================================

export interface DatabaseStats {
  path: string;
  walMode: boolean;
  sizeBytes: number;
  tables: {
    scans: number;
    vulnerabilities: number;
    patches: number;
    formal_proofs: number;
    test_cases: number;
    pr_audit_logs: number;
  };
}

export interface SqlQueryResult<T = any> {
  rows: T[];
  columns: string[];
  rowCount: number;
  executionTimeMs: number;
  query: string;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded';
  engine: string;
  version: string;
  timestamp: string;
  uptimeSeconds: number;
  database: DatabaseStats;
}

export interface VerifyZ3Request {
  vulnerabilityId: string;
  cwe: string;
  patchCandidate: string;
}

export interface RunTestsRequest {
  patchId: string;
}

export interface RunTestsResponse {
  patchId: string;
  total: number;
  passed: number;
  failed: number;
  passRate: number;
  latencyMs: number;
  tests: TestCaseRecord[];
}

export interface MergePrRequest {
  prNumber: number;
  repo: string;
  branch: string;
  author: string;
}

export interface MergePrResponse {
  success: boolean;
  prNumber: number;
  commitSha: string;
  auditLogId: string;
  status: string;
  message: string;
  timestamp: string;
}
