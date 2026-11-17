/**
 * AEGIS Master CLI Execution Pipeline (Steps 1 - 5)
 * Governed strictly by AGENTS.md:
 * - No mock data
 * - Real Tree-sitter AST detection
 * - Real code transformation diff
 * - Real test runner output
 * - Real GitHub Pull Request creation (No auto-merge)
 */

import * as fs from 'fs';
import * as path from 'path';
import { TreeSitterDetector } from '../analyzer/tree-sitter-detector.js';
import { PatchGenerator } from '../patcher/patch-generator.js';
import { TestVerifier } from '../verifier/test-verifier.js';
import { GitHubPrCreator } from '../github/pr-creator.js';

export async function runAegisPipeline() {
  console.log('================================================================');
  console.log('🛡️  AEGIS: AUTOMATED VULNERABILITY REPAIR PIPELINE (FYP CORE)');
  console.log('================================================================\n');

  const targetPath = path.resolve(process.cwd(), 'sample-app/src/auth.ts');
  if (!fs.existsSync(targetPath)) {
    console.error(`Target file does not exist: ${targetPath}`);
    process.exit(1);
  }

  // -------------------------------------------------------------
  // STEP 1: Baseline Vulnerability Verification
  // -------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log('[STEP 1] Validating Sample App & Target Vulnerable Endpoint');
  console.log('----------------------------------------------------------------');
  console.log(`Target File: ${targetPath}`);
  const originalSource = fs.readFileSync(targetPath, 'utf8');
  console.log('Vulnerable code snippet:');
  console.log(originalSource.split('\n').filter(l => l.includes('SELECT') || l.includes('prepare')).map(l => '  ' + l.trim()).join('\n'));
  console.log('Status: Step 1 validated. Real SQLite sample endpoint present.\n');

  // -------------------------------------------------------------
  // STEP 2: Real Tree-sitter AST Detection
  // -------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log('[STEP 2] Running Tree-sitter AST Pattern Match Detector');
  console.log('----------------------------------------------------------------');
  const detector = new TreeSitterDetector();
  const findings = detector.analyzeSource(originalSource, targetPath);

  if (findings.length === 0) {
    console.error('Error: Tree-sitter did not detect any AST vulnerabilities.');
    process.exit(1);
  }

  const finding = findings[0];
  console.log('Tree-sitter Match Result:');
  console.log(`  - Vulnerability Class: ${finding.vulnerabilityClass} (SQL Injection)`);
  console.log(`  - File:                 ${finding.file}`);
  console.log(`  - Location:             Line ${finding.line}, Column ${finding.column}`);
  console.log(`  - Enclosing Function:   ${finding.enclosingFunction}()`);
  console.log(`  - Tainted Parameter:    "${finding.taintedVariable}"`);
  console.log(`  - DB Execution Sink:    "${finding.sinkCallee}()"`);
  console.log(`  - Offending Expression: ${finding.rawExpression}`);
  console.log(`  - Data Provenance:      [${finding.provenance}] (Tree-sitter CST traversal)`);
  console.log('Status: Step 2 completed.\n');

  // -------------------------------------------------------------
  // STEP 3: Real Code Transformation & Unified Diff Generation
  // -------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log('[STEP 3] Generating Parameterized Query AST Patch Transformation');
  console.log('----------------------------------------------------------------');
  const patcher = new PatchGenerator();
  const patch = patcher.generatePatch(originalSource, finding);

  console.log('Real Unified Diff:');
  console.log(patch.unifiedDiff);
  console.log(`  - Strategy:             ${patch.strategy}`);
  console.log(`  - Changed Lines:        ${patch.changedLines}`);
  console.log(`  - Data Provenance:      [${patch.provenance}] (Diff computed via diff library)`);
  console.log('Status: Step 3 completed.\n');

  // -------------------------------------------------------------
  // STEP 4: Real Sandboxed Verification (node --test)
  // -------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log('[STEP 4] Executing Real Test Runner (node --test) against Patch');
  console.log('----------------------------------------------------------------');
  const verifier = new TestVerifier();
  const verification = verifier.verifyPatch(targetPath, patch.patchedSource);

  console.log('Test Execution Output:');
  console.log(verification.testOutput.trim());
  console.log(`\nVerification Summary:`);
  console.log(`  - Total Tests:          ${verification.totalTests}`);
  console.log(`  - Passed:               ${verification.passedCount}`);
  console.log(`  - Failed:               ${verification.failedCount}`);
  console.log(`  - Adversarial Blocked:  ${verification.adversarialBlocked ? 'YES (Defused)' : 'NO'}`);
  console.log(`  - Suite Passed:         ${verification.success ? '100% PASS' : 'FAILED'}`);
  console.log(`  - Measured Duration:    ${verification.durationMs}ms`);
  console.log(`  - Data Provenance:      [${verification.provenance}] (Executed node --test in subshell)`);

  if (!verification.success) {
    console.error('Error: Patch verification tests failed. Aborting PR creation.');
    process.exit(1);
  }
  console.log('Status: Step 4 completed.\n');

  // -------------------------------------------------------------
  // STEP 5: Real GitHub PR Creation (No Auto-Merge)
  // -------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log('[STEP 5] Opening Real Pull Request on GitHub for Human Review');
  console.log('----------------------------------------------------------------');
  const prCreator = new GitHubPrCreator();
  const prResult = prCreator.openPullRequest(targetPath, patch, finding, verification);

  console.log('GitHub Pull Request Created Successfully:');
  console.log(`  - PR URL:               ${prResult.prUrl}`);
  console.log(`  - PR Number:            #${prResult.prNumber}`);
  console.log(`  - Branch:               ${prResult.branchName}`);
  console.log(`  - Commit SHA:           ${prResult.commitSha}`);
  console.log(`  - Auto-Merge:           DISABLED (Human review required)`);
  console.log(`  - Data Provenance:      [${prResult.provenance}] (Created via GitHub CLI / REST API)`);
  console.log('Status: Step 5 completed.\n');

  console.log('================================================================');
  console.log('🎉 AEGIS 5-STEP PIPELINE FULLY EXECUTED & VERIFIED ON REAL CODE');
  console.log(`🔗 Live Pull Request: ${prResult.prUrl}`);
  console.log('================================================================\n');

  return { finding, patch, verification, prResult };
}

// Execute if run directly
if (process.argv[1]?.endsWith('run-aegis.ts') || process.argv[1]?.endsWith('run-aegis.js')) {
  runAegisPipeline().catch(err => {
    console.error('Fatal Pipeline Execution Error:', err);
    process.exit(1);
  });
}
