import type { AuthOutcome, EventCategory } from '../../../types/events';

const SUCCESS_VALUES = new Set([
  'success',
  'succeeded',
  'successful',
  'ok',
  'pass',
  'passed',
  'true',
  'allow',
  'allowed',
  'accept',
  'accepted',
  'granted',
]);

const FAILURE_VALUES = new Set([
  'failure',
  'failed',
  'fail',
  'false',
  'deny',
  'denied',
  'reject',
  'rejected',
  'error',
  'blocked',
  'invalid',
  'unauthorized',
]);

/** Map an explicit outcome value (e.g. event.outcome) to an authentication outcome. */
export function normalizeOutcome(
  value: string | number | boolean | undefined,
): AuthOutcome | undefined {
  if (value === undefined) return undefined;
  const v = String(value).trim().toLowerCase();
  if (SUCCESS_VALUES.has(v)) return 'success';
  if (FAILURE_VALUES.has(v)) return 'failure';
  return undefined;
}

const FAILURE_TEXT =
  /(fail|denied|invalid|reject|bad[_\s-]?password|unauthori[sz]ed|locked|unsuccessful|not[_\s-]?(?:allowed|granted|successful|permitted|authori[sz]ed))/i;
const SUCCESS_TEXT = /(success|succeeded|accepted|\bok\b|allowed|granted|logged[_\s-]?in)/i;

/**
 * Event names use many separators (login_failed, user.login, sso-login). They
 * are normalized to spaces so word boundaries work: in a regex "_" is a word
 * character, so /\bmfa\b/ would not match "mfa_challenge".
 */
const words = (text: string): string => text.replace(/[_.:/\\-]+/g, ' ');

/** Infer an outcome from descriptive text such as an event type "login_failed". */
export function inferOutcomeFromText(text: string | undefined): AuthOutcome | undefined {
  if (!text) return undefined;
  const t = words(text);
  if (FAILURE_TEXT.test(t)) return 'failure';
  if (SUCCESS_TEXT.test(t)) return 'success';
  return undefined;
}

const AUTH_TEXT =
  /(log[_\s-]?[io]n|logon|auth|sign[_\s-]?[io]n|password|credential|\bsso\b|\bmfa\b|2fa|kerberos|ssh)/i;
const SESSION_TEXT = /(session|log[_\s-]?(?:out|off)|sign[_\s-]?out)/i;
const PRIVILEGE_TEXT = /(sudo|privilege|escalat|elevat|\brole\b|admin[_\s-]?grant|\bsu\b)/i;
const CONNECTION_TEXT = /(connect|disconnect|firewall|network|\bconn\b|socket|tcp|udp)/i;

/** Infer an event category from descriptive text in structured records. */
export function inferCategoryFromText(text: string | undefined): EventCategory | undefined {
  if (!text) return undefined;
  const t = words(text);
  if (AUTH_TEXT.test(t)) return 'authentication';
  if (PRIVILEGE_TEXT.test(t)) return 'privilege';
  if (SESSION_TEXT.test(t)) return 'session';
  if (CONNECTION_TEXT.test(t)) return 'connection';
  return undefined;
}
