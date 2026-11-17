/**
 * AEGIS Core: GitHub Pull Request Integration
 *
 * Implements Step 5: Creates a branch with the verified patch, pushes it to GitHub,
 * and opens a real Pull Request for human review with the actual test output attached.
 * Governed by AGENTS.md: NOTHING IS AUTO-MERGED. Every fix requires human review.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { SqlInjectionFinding } from '../analyzer/tree-sitter-detector.js';
import { GeneratedPatch } from '../patcher/patch-generator.js';
import { TestVerificationResult } from '../verifier/test-verifier.js';

export interface PrCreationResult {
  success: boolean;
  prUrl: string;
  prNumber: number;
  branchName: string;
  commitSha: string;
  provenance: 'live';
}

export class GitHubPrCreator {
  /**
   * Opens a real Pull Request on GitHub with the verified patch and actual test runner output
   */
  public openPullRequest(
    targetFilePath: string,
    patch: GeneratedPatch,
    finding: SqlInjectionFinding,
    verification: TestVerificationResult
  ): PrCreationResult {
    const rootDir = process.cwd();
    const branchName = `aegis/fix-cwe89-sqli-${Date.now().toString(36)}`;
    const currentBranch = execSync('git branch --show-current', { cwd: rootDir, encoding: 'utf8' }).trim();

    try {
      // 1. Create and switch to new branch
      execSync(`git checkout -b ${branchName}`, { cwd: rootDir, stdio: 'pipe' });

      // 2. Apply the real patch to target file
      const resolvedTarget = path.resolve(targetFilePath);
      fs.writeFileSync(resolvedTarget, patch.patchedSource, 'utf8');

      // 3. Recompile sample-app
      execSync('npx tsc -p sample-app/tsconfig.json', { cwd: rootDir, stdio: 'pipe' });

      // 4. Stage and commit the fix
      execSync(`git add "${targetFilePath}" "sample-app/dist"`, { cwd: rootDir, stdio: 'pipe' });
      const commitMsg = `fix(security): parameterize SQL query in ${path.basename(targetFilePath)} [AEGIS-CWE89]`;
      execSync(`git commit -m "${commitMsg}"`, { cwd: rootDir, stdio: 'pipe' });
      const commitSha = execSync('git rev-parse HEAD', { cwd: rootDir, encoding: 'utf8' }).trim();

      // 5. Push branch to remote
      execSync(`git push -u origin ${branchName}`, { cwd: rootDir, stdio: 'pipe' });

      // 6. Build PR body with real detection and test results
      const prBody = `## 🛡️ AEGIS Automated Vulnerability Fix: CWE-89

### 1. Detection Summary (Tree-sitter AST Match)
- **Vulnerability Class:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Target File:** \`${finding.file}\`
- **Location:** Line ${finding.line}, Column ${finding.column}
- **Enclosing Function:** \`${finding.enclosingFunction}()\`
- **Tainted Variable:** \`${finding.taintedVariable}\`
- **Database Sink:** \`${finding.sinkCallee}()\`
- **Offending Code:** \`${finding.rawExpression}\`

### 2. Autonomous Patch Transformation
Converted unescaped string concatenation to safe parameter binding:
\`\`\`diff
${patch.unifiedDiff}
\`\`\`

### 3. Real Sandboxed Verification (\`node --test\`)
Real test execution output against the patched code:
\`\`\`text
${verification.testOutput.trim()}
\`\`\`
- **Total Tests:** ${verification.totalTests}
- **Tests Passed:** ${verification.passedCount}
- **Adversarial Exploit Blocked:** ${verification.adversarialBlocked ? 'YES (Defused)' : 'NO'}
- **Verification Duration:** ${verification.durationMs}ms

---
> ⚠️ **Notice (AGENTS.md Compliance):** AEGIS does **not** auto-merge pull requests. A human maintainer must review and approve this fix.`;

      // 7. Open real Pull Request with GitHub CLI (gh)
      const prTitle = `fix(security): parameterize SQL query in ${path.basename(targetFilePath)} [CWE-89]`;
      const prUrl = execSync(
        `gh pr create --title "${prTitle}" --body "${prBody.replace(/"/g, '\\"')}" --base main --head ${branchName}`,
        { cwd: rootDir, encoding: 'utf8' }
      ).trim();

      const prNumberMatch = prUrl.match(/\/pull\/(\d+)/);
      const prNumber = prNumberMatch ? parseInt(prNumberMatch[1], 10) : 0;

      return {
        success: true,
        prUrl,
        prNumber,
        branchName,
        commitSha,
        provenance: 'live'
      };
    } finally {
      // Return to original branch
      try {
        execSync(`git checkout ${currentBranch}`, { cwd: rootDir, stdio: 'pipe' });
      } catch (e) {}
    }
  }
}
