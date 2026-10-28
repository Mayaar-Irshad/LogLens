import { describe, expect, it } from 'vitest';
import {
  daysInMonth,
  parseClfTimestamp,
  parseEpoch,
  parseFlexibleTimestamp,
  parseIsoTimestamp,
  parseOffset,
  parseRfc2822Timestamp,
  parseSyslogTimestamp,
  parseTimezoneSetting,
  SyslogYearTracker,
} from '../../../src/features/log-ingestion/normalization/timestamp';
import { utc } from '../../helpers/ingest';

const opts = { assumedYear: 2026, sourceOffsetMinutes: 0 };

describe('parseOffset', () => {
  it.each([
    ['Z', 0],
    ['UTC', 0],
    ['gmt', 0],
    ['+05:30', 330],
    ['+0530', 330],
    ['-07', -420],
    ['-0700', -420],
    ['UTC+02:00', 120],
  ])('parses %s', (text, minutes) => {
    expect(parseOffset(text)).toBe(minutes);
  });

  it.each(['+25:00', '+05:99', 'EST', '0530', ''])('rejects %s', (text) => {
    expect(parseOffset(text)).toBeNull();
  });

  it('validates the source time-zone setting the same way', () => {
    expect(parseTimezoneSetting('UTC')).toBe(0);
    expect(parseTimezoneSetting('-03:00')).toBe(-180);
    expect(parseTimezoneSetting('Europe/Paris')).toBeNull();
  });
});

describe('parseSyslogTimestamp', () => {
  it('uses the supplied year and treats the time as UTC by default', () => {
    const r = parseSyslogTimestamp('Oct 27 10:15:32', 2026, 0);
    expect(r).toMatchObject({ ok: true, ms: utc(2026, 10, 27, 10, 15, 32), hadZone: false });
  });

  it('applies a source offset for zone-less timestamps', () => {
    // 10:15 at UTC+02:00 is 08:15 UTC.
    const r = parseSyslogTimestamp('Oct 27 10:15:32', 2026, 120);
    expect(r.ok && r.ms).toBe(utc(2026, 10, 27, 8, 15, 32));
  });

  it('accepts single-digit days padded with spaces and fractional seconds', () => {
    const r = parseSyslogTimestamp('Oct  5 01:02:03.250', 2026, 0);
    expect(r.ok && r.ms).toBe(utc(2026, 10, 5, 1, 2, 3, 250));
  });

  it('rejects impossible dates instead of rolling them over', () => {
    expect(parseSyslogTimestamp('Feb 30 10:00:00', 2026, 0).ok).toBe(false);
    expect(parseSyslogTimestamp('Feb 29 10:00:00', 2025, 0).ok).toBe(false);
    expect(parseSyslogTimestamp('Feb 29 10:00:00', 2024, 0).ok).toBe(true);
    expect(parseSyslogTimestamp('Foo 10 10:00:00', 2026, 0)).toMatchObject({ ok: false });
    expect(parseSyslogTimestamp('Oct 10 24:00:00', 2026, 0).ok).toBe(false);
  });
});

describe('parseClfTimestamp', () => {
  it('applies the embedded offset', () => {
    const r = parseClfTimestamp('10/Oct/2026:13:55:36 -0700');
    expect(r).toMatchObject({ ok: true, ms: utc(2026, 10, 10, 20, 55, 36), hadZone: true });
  });

  it('rejects malformed values', () => {
    expect(parseClfTimestamp('32/Oct/2026:13:55:36 +0000').ok).toBe(false);
    expect(parseClfTimestamp('10/Xyz/2026:13:55:36 +0000').ok).toBe(false);
    expect(parseClfTimestamp('2026-10-10').ok).toBe(false);
  });
});

describe('parseIsoTimestamp', () => {
  it.each([
    ['2026-10-27T10:00:00Z', utc(2026, 10, 27, 10)],
    ['2026-10-27T10:00:00.123Z', utc(2026, 10, 27, 10, 0, 0, 123)],
    ['2026-10-27T12:00:00+02:00', utc(2026, 10, 27, 10)],
    ['2026-10-27T05:30:00-0430', utc(2026, 10, 27, 10)],
    ['2026-10-27 10:00:00', utc(2026, 10, 27, 10)],
    ['2026-10-27', utc(2026, 10, 27)],
    ['2026/10/27 10:00:00', utc(2026, 10, 27, 10)],
    ['2026-10-27T10:00:00.123456789Z', utc(2026, 10, 27, 10, 0, 0, 123)],
  ])('parses %s', (text, expected) => {
    const r = parseIsoTimestamp(text);
    expect(r.ok && r.ms).toBe(expected);
  });

  it('uses the default offset only when no zone is present', () => {
    const noZone = parseIsoTimestamp('2026-10-27 10:00:00', -300);
    expect(noZone).toMatchObject({ ok: true, ms: utc(2026, 10, 27, 15), hadZone: false });
    const withZone = parseIsoTimestamp('2026-10-27T10:00:00Z', -300);
    expect(withZone).toMatchObject({ ok: true, ms: utc(2026, 10, 27, 10), hadZone: true });
  });

  it('rejects out-of-range components and years', () => {
    expect(parseIsoTimestamp('2026-13-01T00:00:00Z').ok).toBe(false);
    expect(parseIsoTimestamp('2026-04-31T00:00:00Z').ok).toBe(false);
    expect(parseIsoTimestamp('1969-12-31T00:00:00Z').ok).toBe(false);
    expect(parseIsoTimestamp('2026-10-27T10:61:00Z').ok).toBe(false);
  });

  it('clamps a leap second instead of rolling into the next minute', () => {
    const r = parseIsoTimestamp('2026-12-31T23:59:60Z');
    expect(r.ok && r.ms).toBe(utc(2026, 12, 31, 23, 59, 59));
  });
});

describe('parseEpoch', () => {
  const t = utc(2026, 10, 27, 10, 2, 0);
  it('infers seconds, milliseconds, microseconds and nanoseconds', () => {
    expect(parseEpoch(t / 1000)).toMatchObject({ ok: true, ms: t });
    expect(parseEpoch(t)).toMatchObject({ ok: true, ms: t });
    expect(parseEpoch(t * 1000)).toMatchObject({ ok: true, ms: t });
    expect(parseEpoch(t * 1e6)).toMatchObject({ ok: true, ms: t });
  });

  it('rejects non-positive and out-of-range values', () => {
    expect(parseEpoch(0).ok).toBe(false);
    expect(parseEpoch(-5).ok).toBe(false);
    expect(parseEpoch(Number.NaN).ok).toBe(false);
    expect(parseEpoch(5_000_000_000).ok).toBe(false); // year 2128 in seconds
  });
});

describe('parseRfc2822Timestamp', () => {
  it('parses with and without the weekday', () => {
    expect(parseRfc2822Timestamp('Tue, 27 Oct 2026 10:00:00 +0000')).toMatchObject({
      ok: true,
      ms: utc(2026, 10, 27, 10),
    });
    expect(parseRfc2822Timestamp('27 Oct 2026 12:00 +0200')).toMatchObject({
      ok: true,
      ms: utc(2026, 10, 27, 10),
    });
  });
});

describe('parseFlexibleTimestamp', () => {
  it('dispatches on the value shape', () => {
    const t = utc(2026, 10, 27, 10);
    expect(parseFlexibleTimestamp(t / 1000, opts)).toMatchObject({ ok: true, ms: t });
    expect(parseFlexibleTimestamp(String(t), opts)).toMatchObject({ ok: true, ms: t });
    expect(parseFlexibleTimestamp('2026-10-27T10:00:00Z', opts)).toMatchObject({ ok: true, ms: t });
    expect(parseFlexibleTimestamp('27/Oct/2026:10:00:00 +0000', opts)).toMatchObject({
      ok: true,
      ms: t,
    });
    expect(parseFlexibleTimestamp('Tue, 27 Oct 2026 10:00:00 GMT', opts)).toMatchObject({
      ok: true,
      ms: t,
    });
    expect(parseFlexibleTimestamp('Oct 27 10:00:00', opts)).toMatchObject({ ok: true, ms: t });
    expect(
      parseFlexibleTimestamp('Oct 27 2026 10:00:00', { ...opts, assumedYear: 1999 }),
    ).toMatchObject({ ok: true, ms: t });
  });

  it('refuses ambiguous or unsupported values rather than guessing', () => {
    expect(parseFlexibleTimestamp('03/04/2026 10:00', opts).ok).toBe(false);
    expect(parseFlexibleTimestamp('yesterday', opts).ok).toBe(false);
    expect(parseFlexibleTimestamp('', opts).ok).toBe(false);
    expect(parseFlexibleTimestamp(true, opts).ok).toBe(false);
    expect(parseFlexibleTimestamp('x'.repeat(100), opts).ok).toBe(false);
  });
});

describe('SyslogYearTracker', () => {
  it('rolls the year forward on a December → January transition only', () => {
    const tracker = new SyslogYearTracker(2025);
    expect(tracker.yearFor(12)).toBe(2025);
    expect(tracker.yearFor(12)).toBe(2025);
    expect(tracker.yearFor(1)).toBe(2026);
    expect(tracker.yearFor(1)).toBe(2026);
    expect(tracker.yearFor(3)).toBe(2026);
    // A small backwards step (out-of-order lines) does not change the year.
    expect(tracker.yearFor(2)).toBe(2026);
    expect(tracker.rollovers).toBe(1);
  });

  it('knows month lengths', () => {
    expect(daysInMonth(2024, 2)).toBe(29);
    expect(daysInMonth(2100, 2)).toBe(28);
    expect(daysInMonth(2000, 2)).toBe(29);
    expect(daysInMonth(2026, 9)).toBe(30);
  });
});
