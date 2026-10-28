/**
 * Helpers for handling untrusted strings that originate from log files.
 *
 * React already escapes text, so these helpers are not about HTML injection.
 * They make invisible or deceptive characters visible (terminal escape
 * sequences, NUL bytes, bidirectional overrides that can visually reorder
 * text) and bound the length of values that are displayed or exported.
 */

// C0 controls except tab, DEL, C1 controls.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Bidirectional formatting characters (Trojan Source style spoofing) and zero-width chars.
const BIDI_AND_INVISIBLE = /[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

function toEscape(ch: string): string {
  const code = ch.charCodeAt(0);
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, '0')}`
    : `\\u${code.toString(16).padStart(4, '0')}`;
}

/** Replace control, bidi-override and zero-width characters with visible escapes. */
export function escapeInvisible(value: string): string {
  return value.replace(CONTROL_CHARS, toEscape).replace(BIDI_AND_INVISIBLE, toEscape);
}

/** Escape invisible characters and also make CR/LF visible (for single-line display). */
export function toSingleLine(value: string): string {
  return escapeInvisible(value).replace(/\r/g, '\\r').replace(/\n/g, '\\n');
}

/** Truncate to `max` characters, appending an ellipsis marker when shortened. */
export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

/** Safe, bounded preview of an untrusted record for diagnostics. */
export function previewText(value: string, max = 160): string {
  return truncate(toSingleLine(value), max);
}

/**
 * Normalize an untrusted field value for storage in the event model:
 * trims whitespace, escapes invisible characters, bounds length.
 * Returns undefined for empty or placeholder values.
 */
export function cleanField(value: string | undefined | null, max = 512): string | undefined {
  if (value === undefined || value === null) return undefined;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed === '-') return undefined;
  return truncate(escapeInvisible(trimmed), max);
}

/** Lower-case and strip non-alphanumerics; used for fuzzy key matching. */
export function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Convert free text such as "Login Failed" into a snake_case action label. */
export function toActionLabel(value: string, max = 64): string {
  const label = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return truncate(label, max) || 'event';
}
