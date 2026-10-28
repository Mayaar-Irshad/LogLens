/**
 * Timestamp normalization. Every accepted timestamp becomes epoch milliseconds
 * in UTC. Components are range-checked explicitly instead of relying on the
 * lenient behaviour of `Date.parse`, which silently rolls "Feb 31" into March.
 *
 * Timestamps that carry no zone (syslog, "YYYY-MM-DD HH:MM:SS") are interpreted
 * using a caller-supplied source offset, which defaults to UTC.
 */

export type TimestampResult =
  { ok: true; ms: number; hadZone: boolean } | { ok: false; reason: string };

export const MIN_YEAR = 1970;
export const MAX_YEAR = 2100;

const MONTHS: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

export function monthFromName(name: string): number | undefined {
  return MONTHS[name.slice(0, 3).toLowerCase()];
}

export function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

export function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

const fail = (reason: string): TimestampResult => ({ ok: false, reason });

/**
 * Parse a zone designator: "Z", "UTC", "GMT", "+05:30", "+0530", "-07".
 * Returns minutes east of UTC, or null when invalid.
 */
export function parseOffset(text: string): number | null {
  const t = text.trim();
  if (/^(z|utc|gmt)$/i.test(t)) return 0;
  const m = /^(?:(?:utc|gmt))?([+-])(\d{2}):?(\d{2})?$/i.exec(t);
  if (!m) return null;
  const hours = Number(m[2]);
  const minutes = m[3] === undefined ? 0 : Number(m[3]);
  if (hours > 14 || minutes > 59) return null;
  const total = hours * 60 + minutes;
  return m[1] === '-' ? -total : total;
}

/** Validate a user-supplied source time-zone setting ("UTC" or "±HH:MM"). */
export function parseTimezoneSetting(value: string): number | null {
  return parseOffset(value);
}

interface Components {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millis: number;
}

export function buildTimestamp(
  c: Components,
  offsetMinutes: number,
  hadZone: boolean,
): TimestampResult {
  const { year, month, day, hour, minute } = c;
  let { second } = c;
  if (!Number.isInteger(year) || year < MIN_YEAR || year > MAX_YEAR) {
    return fail(`year ${year} outside supported range ${MIN_YEAR}–${MAX_YEAR}`);
  }
  if (month < 1 || month > 12) return fail(`invalid month ${month}`);
  if (day < 1 || day > daysInMonth(year, month))
    return fail(`invalid day ${day} for month ${month}`);
  if (hour > 23) return fail(`invalid hour ${hour}`);
  if (minute > 59) return fail(`invalid minute ${minute}`);
  if (second > 60) return fail(`invalid second ${second}`);
  if (second === 60) second = 59; // leap second: clamp rather than roll into the next minute
  const ms =
    Date.UTC(year, month - 1, day, hour, minute, second, c.millis) - offsetMinutes * 60_000;
  return { ok: true, ms, hadZone };
}

function fractionToMillis(fraction: string | undefined): number {
  if (!fraction) return 0;
  return Math.floor(Number(`0.${fraction}`) * 1000);
}

const SYSLOG_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/;

/** "Oct 27 10:15:32" (BSD syslog). The year is supplied by the caller. */
export function parseSyslogTimestamp(
  text: string,
  year: number,
  offsetMinutes: number,
): TimestampResult & { month?: number } {
  const m = SYSLOG_RE.exec(text.trim());
  if (!m) return fail('not a syslog timestamp');
  const month = monthFromName(m[1]!);
  if (month === undefined) return fail(`unknown month "${m[1]}"`);
  const result = buildTimestamp(
    {
      year,
      month,
      day: Number(m[2]),
      hour: Number(m[3]),
      minute: Number(m[4]),
      second: Number(m[5]),
      millis: fractionToMillis(m[6]),
    },
    offsetMinutes,
    false,
  );
  return { ...result, month };
}

const CLF_RE =
  /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:\s+([+-]\d{4}|Z))?$/;

/** "10/Oct/2026:13:55:36 -0700" (Apache/Nginx $time_local). */
export function parseClfTimestamp(text: string, defaultOffset = 0): TimestampResult {
  const m = CLF_RE.exec(text.trim());
  if (!m) return fail('not a Common Log Format timestamp');
  const month = monthFromName(m[2]!);
  if (month === undefined) return fail(`unknown month "${m[2]}"`);
  let offset = defaultOffset;
  if (m[8] !== undefined) {
    const parsed = parseOffset(m[8]);
    if (parsed === null) return fail(`invalid zone offset "${m[8]}"`);
    offset = parsed;
  }
  return buildTimestamp(
    {
      year: Number(m[3]),
      month,
      day: Number(m[1]),
      hour: Number(m[4]),
      minute: Number(m[5]),
      second: Number(m[6]),
      millis: fractionToMillis(m[7]),
    },
    offset,
    m[8] !== undefined,
  );
}

const ISO_RE =
  /^(\d{4})-(\d{2})-(\d{2})(?:[T\s](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?\s*(Z|[+-]\d{2}(?::?\d{2})?|UTC|GMT)?$/i;

const SLASH_YMD_RE =
  /^(\d{4})\/(\d{2})\/(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?\s*(Z|[+-]\d{2}(?::?\d{2})?|UTC|GMT)?$/i;

/** ISO 8601 / RFC 3339, including "YYYY-MM-DD HH:MM:SS" without a zone. */
export function parseIsoTimestamp(text: string, defaultOffset = 0): TimestampResult {
  const t = text.trim();
  const m = ISO_RE.exec(t) ?? SLASH_YMD_RE.exec(t);
  if (!m) return fail('not an ISO 8601 timestamp');
  let offset = defaultOffset;
  if (m[8] !== undefined) {
    const parsed = parseOffset(m[8]);
    if (parsed === null) return fail(`invalid zone offset "${m[8]}"`);
    offset = parsed;
  }
  return buildTimestamp(
    {
      year: Number(m[1]),
      month: Number(m[2]),
      day: Number(m[3]),
      hour: m[4] === undefined ? 0 : Number(m[4]),
      minute: m[5] === undefined ? 0 : Number(m[5]),
      second: m[6] === undefined ? 0 : Number(m[6]),
      millis: fractionToMillis(m[7]),
    },
    offset,
    m[8] !== undefined,
  );
}

const RFC2822_RE =
  /^(?:[A-Za-z]{3},?\s+)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|Z|UTC|GMT)?$/;

/** "Tue, 27 Oct 2026 10:00:00 +0000" */
export function parseRfc2822Timestamp(text: string, defaultOffset = 0): TimestampResult {
  const m = RFC2822_RE.exec(text.trim());
  if (!m) return fail('not an RFC 2822 timestamp');
  const month = monthFromName(m[2]!);
  if (month === undefined) return fail(`unknown month "${m[2]}"`);
  let offset = defaultOffset;
  if (m[7] !== undefined) {
    const parsed = parseOffset(m[7]);
    if (parsed === null) return fail(`invalid zone offset "${m[7]}"`);
    offset = parsed;
  }
  return buildTimestamp(
    {
      year: Number(m[3]),
      month,
      day: Number(m[1]),
      hour: Number(m[4]),
      minute: Number(m[5]),
      second: m[6] === undefined ? 0 : Number(m[6]),
      millis: 0,
    },
    offset,
    m[7] !== undefined,
  );
}

const MIN_EPOCH_MS = Date.UTC(MIN_YEAR, 0, 1);
const MAX_EPOCH_MS = Date.UTC(MAX_YEAR, 11, 31, 23, 59, 59);

/**
 * Epoch value in seconds, milliseconds, microseconds or nanoseconds. The unit is
 * inferred from magnitude; values outside 1970–2100 are rejected.
 */
export function parseEpoch(value: number): TimestampResult {
  if (!Number.isFinite(value) || value <= 0) return fail('invalid epoch value');
  let ms: number;
  if (value < 1e11) ms = value * 1000;
  else if (value < 1e14) ms = value;
  else if (value < 1e17) ms = value / 1000;
  else ms = value / 1e6;
  ms = Math.floor(ms);
  if (ms < MIN_EPOCH_MS || ms > MAX_EPOCH_MS) return fail('epoch value outside supported range');
  return { ok: true, ms, hadZone: true };
}

export interface FlexibleTimestampOptions {
  assumedYear: number;
  sourceOffsetMinutes: number;
}

/**
 * Best-effort parser for structured logs (JSONL/CSV) where the timestamp format
 * is not known in advance. Ambiguous day/month orders such as "03/04/2026" are
 * deliberately rejected rather than guessed.
 */
export function parseFlexibleTimestamp(
  value: unknown,
  opts: FlexibleTimestampOptions,
): TimestampResult {
  if (typeof value === 'number') return parseEpoch(value);
  if (typeof value !== 'string') return fail('timestamp is not a string or number');
  const t = value.trim();
  if (t === '') return fail('timestamp is empty');
  if (t.length > 64) return fail('timestamp is too long');
  if (/^\d+(?:\.\d+)?$/.test(t)) return parseEpoch(Number(t));
  const offset = opts.sourceOffsetMinutes;
  if (/^\d{4}[-/]/.test(t)) return parseIsoTimestamp(t, offset);
  if (/^\d{1,2}\/[A-Za-z]{3}\/\d{4}:/.test(t)) return parseClfTimestamp(t, offset);
  if (/^(?:[A-Za-z]{3},?\s+)?\d{1,2}\s+[A-Za-z]{3}\s+\d{4}/.test(t)) {
    return parseRfc2822Timestamp(t, offset);
  }
  const syslogWithYear = /^([A-Za-z]{3}\s+\d{1,2})\s+(\d{4})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/.exec(
    t,
  );
  if (syslogWithYear) {
    return parseSyslogTimestamp(
      `${syslogWithYear[1]} ${syslogWithYear[3]}`,
      Number(syslogWithYear[2]),
      offset,
    );
  }
  if (SYSLOG_RE.test(t)) return parseSyslogTimestamp(t, opts.assumedYear, offset);
  return fail('unrecognized timestamp format');
}

/**
 * Tracks the year for syslog timestamps, which omit it. Starts at the assumed
 * year and increments when the month jumps backwards by six or more months
 * (for example December → January), which indicates a year boundary.
 */
export class SyslogYearTracker {
  private year: number;
  private lastMonth: number | null = null;
  rollovers = 0;

  constructor(assumedYear: number) {
    this.year = assumedYear;
  }

  yearFor(month: number): number {
    if (this.lastMonth !== null && this.lastMonth - month >= 6) {
      this.year += 1;
      this.rollovers += 1;
    }
    this.lastMonth = month;
    return this.year;
  }
}
