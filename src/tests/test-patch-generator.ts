import * as fs from 'fs';
import * as path from 'path';
import { TreeSitterDetector } from '../analyzer/tree-sitter-detector.js';
import { PatchGenerator } from '../patcher/patch-generator.js';

function run() {
  console.log('\n--- AST Patch Generator Run ---');
  const detector = new TreeSitterDetector();
  const patcher = new PatchGenerator();

  const targetPath = path.resolve(process.cwd(), 'sample-app/src/auth.ts');
  const sourceCode = fs.readFileSync(targetPath, 'utf8');

  const findings = detector.analyzeSource(sourceCode, targetPath);
  if (findings.length === 0) {
    console.error('No findings detected.');
    return;
  }

  const patch = patcher.generatePatch(sourceCode, findings[0]);

  console.log('\n[PATCHED SOURCE CODE]:');
  console.log(patch.patchedSource);

  console.log('\n[REAL UNIFIED DIFF]:');
  console.log(patch.unifiedDiff);
}

run();
