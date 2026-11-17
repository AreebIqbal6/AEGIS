// Test Fixture: Vulnerable Comments Component (React/TSX)
// Target for AEGIS AST Taint Localization Engine: CWE-79 Stored XSS

import React from 'react';

interface CommentProps {
  comment: {
    id: string;
    author: string;
    rawHtmlContent: string;
  };
}

export function CommentView({ comment }: CommentProps) {
  // Source: Untrusted raw comment text from user input
  const taintedContent = comment.rawHtmlContent;

  return (
    <div className="comment-card">
      <h4>{comment.author}</h4>
      {/* VULNERABLE SINK: Direct unescaped injection into DOM bypassing React sanitization */}
      <div
        className="comment-body"
        dangerouslySetInnerHTML={{ __html: taintedContent }}
      />
    </div>
  );
}

export function SafeCommentView({ comment }: CommentProps) {
  // Safe handler: React default escaping without dangerouslySetInnerHTML
  return (
    <div className="comment-card">
      <h4>{comment.author}</h4>
      <p className="comment-body">{comment.rawHtmlContent}</p>
    </div>
  );
}
