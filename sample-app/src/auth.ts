import { db } from './db.js';

export interface User {
  id: string;
  username: string;
  role: string;
}

/**
 * Authenticates user by looking up their user ID in the database.
 * VULNERABLE: Uses raw string concatenation instead of parameter binding.
 */
export function findUserById(userId: string): User | undefined {
  const query = "SELECT * FROM users WHERE id = ?";
  const row = db.prepare(query).get(userId) as User | undefined;
  return row;
}
