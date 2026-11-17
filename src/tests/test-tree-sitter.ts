import { TreeSitterDetector } from '../analyzer/tree-sitter-detector.js';
import * as path from 'path';

function run() {
  console.log('\n--- Tree-sitter AST Detection Run ---');
  const detector = new TreeSitterDetector();
  const targetPath = path.resolve(process.cwd(), 'sample-app/src/auth.ts');
  
  console.log(`Analyzing real sample file: ${targetPath}`);
  const findings = detector.analyzeFile(targetPath);

  console.log(`Findings count: ${findings.length}`);
  for (const f of findings) {
    console.log(JSON.stringify(f, null, 2));
  }
}

run();
