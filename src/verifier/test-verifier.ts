/**
 * AEGIS Core: Sandboxed Test Verifier
 *
 * Executes the real test suite against patched source code.
 * Evaluates both regression tests (normal functionality) and
 * adversarial injection payload attacks to confirm exploit defusal.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export interface TestVerificationResult {
  success: boolean;
  totalTests: number;
  passedCount: number;
  failedCount: number;
  testOutput: string;
  durationMs: number;
  adversarialBlocked: boolean;
  provenance: 'live';
}

export class TestVerifier {
  /**
   * Applies the patch to sample-app/src/auth.ts, compiles with tsc,
   * runs `node --test`, and returns the real output.
   */
  public verifyPatch(targetFilePath: string, patchedContent: string): TestVerificationResult {
    const resolvedTarget = path.resolve(targetFilePath);
    const backupContent = fs.readFileSync(resolvedTarget, 'utf8');
    const start = performance.now();

    try {
      // 1. Apply patched source code
      fs.writeFileSync(resolvedTarget, patchedContent, 'utf8');

      // 2. Recompile sample-app
      const rootDir = process.cwd();
      execSync('npx tsc -p sample-app/tsconfig.json', { cwd: rootDir, stdio: 'pipe' });

      // 3. Execute real test suite with node --test
      let testOutput = '';
      let testExitCode = 0;

      try {
        const stdout = execSync('node --test sample-app/dist/test/auth.test.js', {
          cwd: rootDir,
          encoding: 'utf8'
        });
        testOutput = stdout;
      } catch (err: any) {
        testExitCode = err.status || 1;
        testOutput = (err.stdout || '') + '\n' + (err.stderr || '');
      }

      const durationMs = Math.round((performance.now() - start) * 100) / 100;

      // 4. Parse real test output metrics
      const passMatch = testOutput.match(/ℹ pass (\d+)/);
      const failMatch = testOutput.match(/ℹ fail (\d+)/);
      const totalMatch = testOutput.match(/ℹ tests (\d+)/);

      const passedCount = passMatch ? parseInt(passMatch[1], 10) : 0;
      const failedCount = failMatch ? parseInt(failMatch[1], 10) : 0;
      const totalTests = totalMatch ? parseInt(totalMatch[1], 10) : (passedCount + failedCount);

      // Check if the adversarial test passed
      const adversarialBlocked = testOutput.includes('✔ should prevent SQL injection bypass');

      return {
        success: testExitCode === 0 && failedCount === 0,
        totalTests,
        passedCount,
        failedCount,
        testOutput,
        durationMs,
        adversarialBlocked,
        provenance: 'live'
      };
    } finally {
      // Restore backup after test run to leave workspace clean
      fs.writeFileSync(resolvedTarget, backupContent, 'utf8');
      // Recompile original to restore dist state
      execSync('npx tsc -p sample-app/tsconfig.json', { cwd: process.cwd(), stdio: 'pipe' });
    }
  }
}
