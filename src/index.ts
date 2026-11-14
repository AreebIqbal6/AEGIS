import * as fs from 'fs';
import * as path from 'path';
import { TaintAnalyzer } from './analyzer/taint-analyzer.js';

export async function main() {
  console.log('\n=============================================================');
  console.log('🛡️  AEGIS CORE: AUTONOMOUS AST TAINT LOCALIZATION ENGINE');
  console.log('=============================================================\n');

  const targetPath = process.argv[2] || path.resolve(process.cwd(), 'test-fixtures/vulnerable-auth.ts');

  if (!fs.existsSync(targetPath)) {
    console.error(`❌ Error: Target file not found at ${targetPath}`);
    process.exit(1);
  }

  console.log(`[INGEST] Ingesting source file: ${targetPath}`);
  const startTime = performance.now();

  const code = fs.readFileSync(targetPath, 'utf8');
  const analyzer = new TaintAnalyzer();

  console.log('[PARSER] Constructing Abstract Syntax Tree (AST)...');
  const reports = analyzer.analyze(code, targetPath);
  const elapsed = (performance.now() - startTime).toFixed(2);

  console.log(`[COMPLETE] AST traversal completed in ${elapsed}ms\n`);

  if (reports.length === 0) {
    console.log('✅ [CLEAN] No unvalidated taint sinks detected. Code satisfies AST safety predicates.');
    process.exit(0);
  }

  console.log(`🚨 [ALERT] DETECTED ${reports.length} CRITICAL VULNERABILITY SINK(S):\n`);

  for (const report of reports) {
    console.log('-------------------------------------------------------------');
    console.log(`ID:                  ${report.id}`);
    console.log(`Classification:      ${report.cwe}`);
    console.log(`Severity:            ${report.severity}`);
    console.log(`Location:            ${report.filePath}:${report.line}:${report.column}`);
    console.log(`Enclosing Function:  ${report.enclosingFunction}()`);
    console.log(`Tainted Sources:     [${report.taintedVariables.join(', ')}]`);
    console.log(`Execution Sink:      ${report.sinkCallee}()`);
    console.log(`Offending Statement: "${report.rawCodeSnippet}"`);
    console.log('-------------------------------------------------------------\n');
  }

  console.log('🔒 AEGIS PIPELINE STATUS: DISPATCHING TO NEURO-SYMBOLIC SURGEON (Z3)...\n');
}

main().catch(err => {
  console.error('Fatal Analyzer Error:', err);
  process.exit(1);
});
