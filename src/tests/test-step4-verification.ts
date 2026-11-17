import * as fs from 'fs';
import * as path from 'path';
import { TreeSitterDetector } from '../analyzer/tree-sitter-detector.js';
import { PatchGenerator } from '../patcher/patch-generator.js';
import { TestVerifier } from '../verifier/test-verifier.js';

function run() {
  console.log('====================================================');
  console.log('🛡️  AEGIS PIPELINE: STEP 1 - 4 GENUINE VERIFICATION');
  console.log('====================================================\n');

  const targetPath = path.resolve(process.cwd(), 'sample-app/src/auth.ts');
  const sourceCode = fs.readFileSync(targetPath, 'utf8');

  // STEP 2: Real Tree-sitter AST Detection
  console.log('[STEP 2] Running Tree-sitter AST Detection...');
  const detector = new TreeSitterDetector();
  const findings = detector.analyzeSource(sourceCode, targetPath);
  console.log(`  -> Found ${findings.length} AST vulnerability finding(s).`);
  console.log(`  -> Target: line ${findings[0].line}, variable: "${findings[0].taintedVariable}", sink: "${findings[0].sinkCallee}"\n`);

  // STEP 3: Real Code Transformation & Diff
  console.log('[STEP 3] Running AST Patch Synthesizer & Code Transformer...');
  const patcher = new PatchGenerator();
  const patch = patcher.generatePatch(sourceCode, findings[0]);
  console.log('  -> Generated Real Unified Diff:');
  console.log('----------------------------------------------------');
  console.log(patch.unifiedDiff);
  console.log('----------------------------------------------------\n');

  // STEP 4: Real Sandboxed Test & Adversarial Payload Execution
  console.log('[STEP 4] Executing Real Test Runner (node --test) against Patched Code...');
  const verifier = new TestVerifier();
  const verification = verifier.verifyPatch(targetPath, patch.patchedSource);

  console.log('  -> Test Runner Output:');
  console.log('----------------------------------------------------');
  console.log(verification.testOutput.trim());
  console.log('----------------------------------------------------');
  console.log(`  -> Total Tests Run:      ${verification.totalTests}`);
  console.log(`  -> Tests Passed:          ${verification.passedCount}`);
  console.log(`  -> Tests Failed:          ${verification.failedCount}`);
  console.log(`  -> Adversarial Blocked:   ${verification.adversarialBlocked ? 'YES (Exploit Defused)' : 'NO'}`);
  console.log(`  -> Test Suite Success:    ${verification.success ? 'PASSED (100%)' : 'FAILED'}`);
  console.log(`  -> Measured Duration:     ${verification.durationMs}ms`);
  console.log(`  -> Provenance Tag:        [${verification.provenance}]`);
  console.log('====================================================\n');
}

run();
