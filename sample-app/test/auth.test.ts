import { describe, it } from 'node:test';
import assert from 'node:assert';
import { findUserById } from '../src/auth.js';

describe('Authentication & User Lookup Suite', () => {
  it('should authenticate valid user alice_admin with id user_admin', () => {
    const user = findUserById('user_admin');
    assert.ok(user, 'User must exist');
    assert.strictEqual(user.username, 'alice_admin');
    assert.strictEqual(user.role, 'admin');
  });

  it('should authenticate valid user bob_user with id user_bob', () => {
    const user = findUserById('user_bob');
    assert.ok(user, 'User must exist');
    assert.strictEqual(user.username, 'bob_user');
  });

  it('should return undefined for nonexistent user_ghost', () => {
    const user = findUserById('user_ghost');
    assert.strictEqual(user, undefined);
  });
});

describe('Adversarial Security Injection Check', () => {
  it('should prevent SQL injection bypass using payload: \' OR \'1\'=\'1', () => {
    const attackPayload = "' OR '1'='1";
    const result = findUserById(attackPayload);
    // In a patched / secure system, no user has the literal ID "' OR '1'='1",
    // so result MUST be undefined.
    assert.strictEqual(result, undefined, 'SQL injection payload must NOT bypass authentication!');
  });
});
