// Test Fixture: Vulnerable Authentication Controller
// Target for AEGIS AST Taint Localization Engine

import { Request, Response } from 'express';

// Simulated DB driver
const db = {
  query: async (sql: string, params?: any[]) => {
    return { id: 1, email: 'admin@aegis.dev', role: 'admin' };
  }
};

export async function loginHandler(req: Request, res: Response) {
  // Source 1: Untrusted user input extracted from request body
  const { userId, tenantId } = req.body;

  // Benign intermediate variable
  const requestTimestamp = Date.now();

  // VULNERABLE SINK (Line 18): Raw string concatenation reaching db.query
  // Tainted variable `userId` directly concatenated into SQL query string
  const user = await db.query("SELECT * FROM users WHERE id = '" + userId + "' AND tenant = '" + tenantId + "'");

  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  return res.json({ success: true, user, timestamp: requestTimestamp });
}

export async function safeProfileHandler(req: Request, res: Response) {
  // Safe handler using parameterized query
  const { id } = req.params;
  const profile = await db.query("SELECT * FROM profiles WHERE id = $1", [id]);
  return res.json({ profile });
}
