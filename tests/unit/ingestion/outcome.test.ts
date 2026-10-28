import { describe, expect, it } from 'vitest';
import {
  inferCategoryFromText,
  inferOutcomeFromText,
  normalizeOutcome,
} from '../../../src/features/log-ingestion/normalization/outcome';

describe('outcome normalization', () => {
  it.each([
    ['success', 'success'],
    ['SUCCEEDED', 'success'],
    [true, 'success'],
    ['allowed', 'success'],
    ['failure', 'failure'],
    [' Denied ', 'failure'],
    [false, 'failure'],
    ['blocked', 'failure'],
  ] as const)('maps %j to %s', (value, expected) => {
    expect(normalizeOutcome(value)).toBe(expected);
  });

  it('leaves ambiguous values unmapped instead of guessing', () => {
    expect(normalizeOutcome(undefined)).toBeUndefined();
    expect(normalizeOutcome('unknown')).toBeUndefined();
    expect(normalizeOutcome(0)).toBeUndefined();
    expect(normalizeOutcome(1)).toBeUndefined();
  });

  it('infers outcomes from descriptive text', () => {
    expect(inferOutcomeFromText('LOGIN_FAILED')).toBe('failure');
    expect(inferOutcomeFromText('user.login.denied')).toBe('failure');
    expect(inferOutcomeFromText('bad_password')).toBe('failure');
    expect(inferOutcomeFromText('login_success')).toBe('success');
    expect(inferOutcomeFromText('user logged in')).toBe('success');
    expect(inferOutcomeFromText('page_view')).toBeUndefined();
    expect(inferOutcomeFromText(undefined)).toBeUndefined();
  });

  it('infers categories from descriptive text', () => {
    expect(inferCategoryFromText('user_login')).toBe('authentication');
    expect(inferCategoryFromText('SignIn')).toBe('authentication');
    expect(inferCategoryFromText('mfa_challenge')).toBe('authentication');
    expect(inferCategoryFromText('sudo_exec')).toBe('privilege');
    expect(inferCategoryFromText('role_assigned')).toBe('privilege');
    expect(inferCategoryFromText('logout')).toBe('session');
    expect(inferCategoryFromText('session_start')).toBe('session');
    expect(inferCategoryFromText('firewall_drop')).toBe('connection');
    expect(inferCategoryFromText('file_upload')).toBeUndefined();
    expect(inferCategoryFromText(undefined)).toBeUndefined();
  });
});
