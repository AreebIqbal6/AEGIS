/**
 * AEGIS Core: AST Taint Localization Engine
 * Parses TypeScript/JavaScript ASTs, tracks untrusted data flow,
 * and pinpoints vulnerable sinks with line/column precision.
 */

import * as parser from '@babel/parser';
import traverseModule from '@babel/traverse';
import * as t from '@babel/types';

// Handle ESM / CJS interoperability for @babel/traverse
const traverse = (traverseModule as any).default || traverseModule;

export interface VulnerabilityReport {
  id: string;
  cwe: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  filePath: string;
  line: number;
  column: number;
  enclosingFunction: string;
  taintedVariables: string[];
  sinkCallee: string;
  rawCodeSnippet: string;
  timestamp: string;
}

export class TaintAnalyzer {
  private knownSources = new Set(['req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies']);
  private knownDatabaseSinks = new Set(['db.query', 'connection.execute', 'pool.query', 'client.query']);

  /**
   * Analyzes source code string and returns all isolated vulnerabilities
   */
  public analyze(code: string, filePath: string): VulnerabilityReport[] {
    const ast = parser.parse(code, {
      sourceType: 'module',
      plugins: ['typescript', 'decorators-legacy', 'asyncGenerators']
    });

    const taintedVariables = new Set<string>();
    const reports: VulnerabilityReport[] = [];

    // Pass 1: Identify and Propagate Tainted Variables
    traverse(ast, {
      VariableDeclarator: (path: any) => {
        const id = path.node.id;
        const init = path.node.init;

        if (!init) return;

        // Check 1: Destructuring from request object: const { userId } = req.body;
        if (t.isObjectPattern(id) && t.isMemberExpression(init)) {
          const sourceName = this.getMemberExpressionString(init);
          if (this.isSource(sourceName)) {
            for (const prop of id.properties) {
              if (t.isObjectProperty(prop) && t.isIdentifier(prop.key)) {
                taintedVariables.add(prop.key.name);
              }
            }
          }
        }

        // Check 2: Direct assignment: const id = req.body.id;
        if (t.isIdentifier(id) && t.isMemberExpression(init)) {
          const sourceName = this.getMemberExpressionString(init);
          if (this.isSource(sourceName)) {
            taintedVariables.add(id.name);
          }
        }
      }
    });

    // Pass 2: Detect Tainted Data Flow reaching Execution Sinks
    traverse(ast, {
      CallExpression: (path: any) => {
        const callee = path.node.callee;
        let calleeName = '';

        if (t.isMemberExpression(callee)) {
          calleeName = this.getMemberExpressionString(callee);
        } else if (t.isIdentifier(callee)) {
          calleeName = callee.name;
        }

        // Check if callee is a database query sink
        if (this.knownDatabaseSinks.has(calleeName)) {
          const firstArg = path.node.arguments[0];

          if (firstArg) {
            const detectedTaints = this.extractTaintedVariablesFromExpression(firstArg, taintedVariables);

            if (detectedTaints.length > 0) {
              const loc = path.node.loc;
              const functionParent = path.getFunctionParent();
              let funcName = 'anonymous';

              if (functionParent) {
                if (functionParent.node.id) {
                  funcName = functionParent.node.id.name;
                } else if (t.isVariableDeclarator(functionParent.parent)) {
                  funcName = (functionParent.parent.id as any).name || 'anonymous';
                }
              }

              // Extract raw snippet lines
              const codeLines = code.split('\n');
              const lineIndex = loc ? loc.start.line - 1 : 0;
              const snippet = codeLines[lineIndex]?.trim() || '';

              reports.push({
                id: `AEGIS-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`,
                cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
                severity: 'CRITICAL',
                title: 'SQL Injection via Unsanitized Input Concatenation',
                filePath,
                line: loc ? loc.start.line : 1,
                column: loc ? loc.start.column : 0,
                enclosingFunction: funcName,
                taintedVariables: detectedTaints,
                sinkCallee: calleeName,
                rawCodeSnippet: snippet,
                timestamp: new Date().toISOString()
              });
            }
          }
        }
      }
    });

    return reports;
  }

  private isSource(str: string): boolean {
    for (const source of this.knownSources) {
      if (str.startsWith(source)) return true;
    }
    return false;
  }

  private getMemberExpressionString(node: t.MemberExpression): string {
    const parts: string[] = [];
    let current: any = node;

    while (current && t.isMemberExpression(current)) {
      if (t.isIdentifier(current.property)) {
        parts.unshift(current.property.name);
      }
      current = current.object;
    }

    if (current && t.isIdentifier(current)) {
      parts.unshift(current.name);
    }

    return parts.join('.');
  }

  private extractTaintedVariablesFromExpression(expr: t.Node, taintedSet: Set<string>): string[] {
    const found: string[] = [];

    // Case 1: Binary Expression string concatenation ("SELECT ... " + userId)
    if (t.isBinaryExpression(expr)) {
      found.push(...this.extractTaintedVariablesFromExpression(expr.left, taintedSet));
      found.push(...this.extractTaintedVariablesFromExpression(expr.right, taintedSet));
    }

    // Case 2: Template Literals (`SELECT ... ${userId}`)
    else if (t.isTemplateLiteral(expr)) {
      for (const elem of expr.expressions) {
        found.push(...this.extractTaintedVariablesFromExpression(elem, taintedSet));
      }
    }

    // Case 3: Identifier reference
    else if (t.isIdentifier(expr)) {
      if (taintedSet.has(expr.name)) {
        found.push(expr.name);
      }
    }

    return Array.from(new Set(found));
  }
}
