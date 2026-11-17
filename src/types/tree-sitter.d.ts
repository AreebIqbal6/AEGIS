declare module 'tree-sitter' {
  export interface Point {
    row: number;
    column: number;
  }

  export interface SyntaxNode {
    type: string;
    text: string;
    startPosition: Point;
    endPosition: Point;
    startIndex: number;
    endIndex: number;
    parent: SyntaxNode | null;
    children: SyntaxNode[];
    childCount: number;
    namedChildren: SyntaxNode[];
    namedChildCount: number;
    childForFieldName(fieldName: string): SyntaxNode | null;
  }

  export interface Tree {
    rootNode: SyntaxNode;
  }

  export default class Parser {
    setLanguage(language: any): void;
    parse(input: string): Tree;
  }
}

declare module 'tree-sitter-typescript' {
  export const typescript: any;
  export const tsx: any;
}
