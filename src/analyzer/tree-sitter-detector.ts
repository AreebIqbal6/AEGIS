/**
 * AEGIS Core: Tree-Sitter AST Taint Detector
 *
 * Scans TypeScript / JavaScript files using tree-sitter.
 * Traverses the concrete syntax tree, tracks function parameter taint,
 * and flags unparameterized variable concatenations reaching SQL execution sinks.
 */

import Parser, { SyntaxNode } from 'tree-sitter';
import { typescript } from 'tree-sitter-typescript';
import * as fs from 'fs';
import * as path from 'path';

export interface SqlInjectionFinding {
  vulnerabilityClass: 'CWE-89';
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  enclosingFunction: string;
  taintedVariable: string;
  sinkCallee: string;
  rawExpression: string;
  fullStatement: string;
  provenance: 'live';
}

export class TreeSitterDetector {
  private parser: Parser;
  private dbSinkPatterns = ['prepare', 'query', 'execute', 'run', 'get', 'all'];

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(typescript);
  }

  /**
   * Analyzes a TypeScript file and returns genuine AST-matched findings
   */
  public analyzeFile(filePath: string): SqlInjectionFinding[] {
    const resolvedPath = path.resolve(filePath);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`Target file not found: ${resolvedPath}`);
    }

    const sourceCode = fs.readFileSync(resolvedPath, 'utf8');
    return this.analyzeSource(sourceCode, resolvedPath);
  }

  /**
   * Analyzes raw source code string using Tree-sitter CST
   */
  public analyzeSource(sourceCode: string, filePath: string = 'inline.ts'): SqlInjectionFinding[] {
    const tree = this.parser.parse(sourceCode);
    const findings: SqlInjectionFinding[] = [];

    // Traverse root AST
    this.traverseForFunctions(tree.rootNode, sourceCode, filePath, findings);

    return findings;
  }

  private traverseForFunctions(
    node: SyntaxNode,
    sourceCode: string,
    filePath: string,
    findings: SqlInjectionFinding[]
  ): void {
    if (
      node.type === 'function_declaration' ||
      node.type === 'function_expression' ||
      node.type === 'arrow_function' ||
      node.type === 'method_definition'
    ) {
      this.analyzeFunctionScope(node, sourceCode, filePath, findings);
    }

    for (const child of node.children) {
      this.traverseForFunctions(child, sourceCode, filePath, findings);
    }
  }

  private analyzeFunctionScope(
    funcNode: SyntaxNode,
    sourceCode: string,
    filePath: string,
    findings: SqlInjectionFinding[]
  ): void {
    // 1. Extract function name
    let funcName = 'anonymous';
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) {
      funcName = nameNode.text;
    }

    // 2. Extract function parameters (Taint Sources)
    const taintedParams = new Set<string>();
    const paramsNode = funcNode.childForFieldName('parameters');
    if (paramsNode) {
      this.collectParameterIdentifiers(paramsNode, taintedParams);
    }

    if (taintedParams.size === 0) {
      return;
    }

    // 3. Track variable declarations inside function body
    // Map: variableName -> { isConcatenated: boolean, taintedVar: string, rawText: string, node: SyntaxNode }
    const variableTaintMap = new Map<
      string,
      { taintedVar: string; rawText: string; node: SyntaxNode }
    >();

    this.collectVariableDeclarations(funcNode, taintedParams, variableTaintMap);

    // 4. Find call expressions reaching database sinks
    this.findDatabaseCallSinks(
      funcNode,
      taintedParams,
      variableTaintMap,
      funcName,
      filePath,
      findings
    );
  }

  private collectParameterIdentifiers(node: SyntaxNode, set: Set<string>): void {
    if (node.type === 'identifier') {
      set.add(node.text);
      return;
    }
    for (const child of node.children) {
      // Avoid collecting type annotations as parameter names
      if (child.type !== 'type_annotation') {
        this.collectParameterIdentifiers(child, set);
      }
    }
  }

  private collectVariableDeclarations(
    node: SyntaxNode,
    taintedParams: Set<string>,
    map: Map<string, { taintedVar: string; rawText: string; node: SyntaxNode }>
  ): void {
    if (node.type === 'variable_declarator') {
      const nameNode = node.childForFieldName('name');
      const valueNode = node.childForFieldName('value');

      if (nameNode && valueNode) {
        const varName = nameNode.text;
        const taintedVar = this.getConcatenatedTaint(valueNode, taintedParams);

        if (taintedVar) {
          map.set(varName, {
            taintedVar,
            rawText: valueNode.text,
            node: valueNode
          });
        }
      }
    }

    for (const child of node.children) {
      this.collectVariableDeclarations(child, taintedParams, map);
    }
  }

  private getConcatenatedTaint(node: SyntaxNode, taintedParams: Set<string>): string | null {
    // Check 1: Binary Expression with + operator
    if (node.type === 'binary_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      const operator = node.children.find((c) => c.text === '+');

      if (operator) {
        if (left) {
          const taintL = this.getConcatenatedTaint(left, taintedParams);
          if (taintL) return taintL;
        }
        if (right) {
          const taintR = this.getConcatenatedTaint(right, taintedParams);
          if (taintR) return taintR;
        }
      }
    }

    // Check 2: Template String (`SELECT ... ${userId}`)
    if (node.type === 'template_string') {
      for (const child of node.children) {
        if (child.type === 'template_substitution') {
          for (const subChild of child.children) {
            if (subChild.type === 'identifier' && taintedParams.has(subChild.text)) {
              return subChild.text;
            }
          }
        }
      }
    }

    // Check 3: Identifier reference to parameter
    if (node.type === 'identifier' && taintedParams.has(node.text)) {
      return node.text;
    }

    return null;
  }

  private findDatabaseCallSinks(
    node: SyntaxNode,
    taintedParams: Set<string>,
    variableTaintMap: Map<string, { taintedVar: string; rawText: string; node: SyntaxNode }>,
    enclosingFunction: string,
    filePath: string,
    findings: SqlInjectionFinding[]
  ): void {
    if (node.type === 'call_expression') {
      const func = node.childForFieldName('function');
      const args = node.childForFieldName('arguments');

      if (func && args && args.namedChildren.length > 0) {
        const calleeText = func.text;
        const isDbSink = this.dbSinkPatterns.some((pattern) => calleeText.includes(pattern));

        if (isDbSink) {
          const firstArg = args.namedChildren[0];
          let detectedTaint: string | null = null;
          let offendingExprText = '';

          // Case A: Argument is a variable previously assigned a concatenated string
          if (firstArg.type === 'identifier' && variableTaintMap.has(firstArg.text)) {
            const mapped = variableTaintMap.get(firstArg.text)!;
            detectedTaint = mapped.taintedVar;
            offendingExprText = mapped.rawText;
          }

          // Case B: Argument is a direct concatenation expression inline
          else {
            const directTaint = this.getConcatenatedTaint(firstArg, taintedParams);
            if (directTaint && (firstArg.type === 'binary_expression' || firstArg.type === 'template_string')) {
              detectedTaint = directTaint;
              offendingExprText = firstArg.text;
            }
          }

          if (detectedTaint) {
            // Locate statement parent for full line context
            let stmt = node;
            while (stmt.parent && !stmt.type.endsWith('_statement') && !stmt.type.endsWith('_declaration')) {
              stmt = stmt.parent;
            }

            findings.push({
              vulnerabilityClass: 'CWE-89',
              file: filePath,
              line: node.startPosition.row + 1,
              column: node.startPosition.column + 1,
              endLine: node.endPosition.row + 1,
              endColumn: node.endPosition.column + 1,
              enclosingFunction,
              taintedVariable: detectedTaint,
              sinkCallee: calleeText,
              rawExpression: offendingExprText,
              fullStatement: stmt.text,
              provenance: 'live'
            });
          }
        }
      }
    }

    for (const child of node.children) {
      this.findDatabaseCallSinks(
        child,
        taintedParams,
        variableTaintMap,
        enclosingFunction,
        filePath,
        findings
      );
    }
  }
}
