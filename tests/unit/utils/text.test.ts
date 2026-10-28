import { describe, expect, it } from 'vitest';
import {
  cleanField,
  escapeInvisible,
  normalizeKey,
  previewText,
  toActionLabel,
  toSingleLine,
  truncate,
} from '../../../src/utils/text';
import {
  fromDateTimeInput,
  formatDuration,
  formatTimestamp,
  toDateTimeInput,
  formatAxisTime,
  formatBytes,
  formatPercent,
} from '../../../src/utils/format';
import { clampNumber } from '../../../src/utils/validation';
import { hash53 } from '../../../src/utils/hash';

describe('text helpers', () => {
  it('makes control, bidi and zero-width characters visible', () => {
    expect(escapeInvisible('a\u0000b\u001bc\u202ed\u200be\u007f')).toBe(
      'a\\x00b\\x1bc\\u202ed\\u200be\\x7f',
    );
    expect(escapeInvisible('tab\tok')).toBe('tab\tok');
  });

  it('renders line breaks visibly for single-line contexts', () => {
    expect(toSingleLine('a\r\nb')).toBe('a\\r\\nb');
  });

  it('truncates with an ellipsis', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 4)).toBe('abc');
    expect(previewText('x'.repeat(500)).length).toBe(160);
  });

  it('cleans fields and drops placeholders', () => {
    expect(cleanField('  value ')).toBe('value');
    expect(cleanField('-')).toBeUndefined();
    expect(cleanField('')).toBeUndefined();
    expect(cleanField(null)).toBeUndefined();
    expect(cleanField('abcdef', 3)).toBe('ab…');
  });

  it('normalizes keys and action labels', () => {
    expect(normalizeKey('Source.IP_Address')).toBe('sourceipaddress');
    expect(toActionLabel('  Login Failed!! ')).toBe('login_failed');
    expect(toActionLabel('!!!')).toBe('event');
  });
});

describe('format helpers', () => {
  const t = Date.UTC(2026, 9, 27, 14, 5, 9);
  it('formats timestamps in UTC explicitly', () => {
    expect(formatTimestamp(t, 'UTC')).toBe('2026-10-27 14:05:09 UTC');
    expect(formatTimestamp(undefined, 'UTC')).toBe('—');
  });

  it('round-trips datetime-local values in UTC', () => {
    expect(toDateTimeInput(t, 'UTC')).toBe('2026-10-27T14:05:09');
    expect(fromDateTimeInput('2026-10-27T14:05:09', 'UTC')).toBe(t);
    expect(fromDateTimeInput('2026-10-27T14:05', 'UTC')).toBe(t - 9000);
    expect(fromDateTimeInput('nonsense', 'UTC')).toBeUndefined();
    const local = fromDateTimeInput(toDateTimeInput(t, 'local'), 'local');
    expect(local).toBe(t);
  });

  it('formats durations, sizes and percentages', () => {
    expect(formatDuration(5_000)).toBe('5s');
    expect(formatDuration(65_000)).toBe('1m 05s');
    expect(formatDuration(3 * 3600_000 + 60_000)).toBe('3h 01m');
    expect(formatDuration(50 * 3600_000)).toBe('2d 2h');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatPercent(1, 3)).toBe('33%');
    expect(formatPercent(1, 200)).toBe('0.5%');
    expect(formatPercent(1, 0)).toBe('0%');
  });

  it('adapts axis labels to the span', () => {
    expect(formatAxisTime(t, 'UTC', 3600_000)).toBe('14:05');
    expect(formatAxisTime(t, 'UTC', 3 * 86_400_000)).toBe('10-27 14:05');
    expect(formatAxisTime(t, 'UTC', 30 * 86_400_000)).toBe('2026-10-27');
  });
});

describe('validation and hashing', () => {
  it('clamps numbers', () => {
    const spec = { min: 1, max: 10, integer: true, default: 5 };
    expect(clampNumber(20, spec)).toBe(10);
    expect(clampNumber('3.6', spec)).toBe(4);
    expect(clampNumber(undefined, spec)).toBe(5);
    expect(clampNumber(Infinity, spec)).toBe(5);
    expect(clampNumber({}, spec)).toBe(5);
  });

  it('hashes deterministically', () => {
    expect(hash53('abc')).toBe(hash53('abc'));
    expect(hash53('abc')).not.toBe(hash53('abd'));
  });
});
