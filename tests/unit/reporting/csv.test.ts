import { describe, expect, it } from 'vitest';
import {
  csvCell,
  csvRow,
  eventsToCsv,
  EVENT_CSV_COLUMNS,
} from '../../../src/features/reporting/csv';
import { build, req, T0 } from '../../helpers/events';

describe('CSV encoding', () => {
  it('quotes every cell and doubles inner quotes', () => {
    expect(csvCell('a"b')).toBe('"a""b"');
    expect(csvCell(undefined)).toBe('""');
    expect(csvCell(42)).toBe('"42"');
    expect(csvRow(['x', 1, null])).toBe('"x","1",""');
  });

  it.each([
    '=1+1',
    '+SUM(A1)',
    '-2+3',
    '@cmd',
    '\t=x',
    '\r=x',
    '  =HYPERLINK("http://example.test")',
    '＝1',
  ])('neutralizes spreadsheet formula trigger in %j', (value) => {
    expect(csvCell(value).startsWith(`"'`)).toBe(true);
  });

  it('leaves numbers and ordinary text alone', () => {
    expect(csvCell(-5)).toBe('"-5"');
    expect(csvCell('GET /index.html')).toBe('"GET /index.html"');
  });
});

describe('eventsToCsv', () => {
  const events = build([
    req(T0, '192.0.2.1', '/a', 200, { userAgent: '=HYPERLINK("https://example.test","x")' }),
    { ...req(T0, '192.0.2.2', '/b', 404), raw: 'raw "line" with <script>' },
  ]);

  it('excludes raw log lines unless explicitly requested', () => {
    const out = eventsToCsv(events, [0, 1], { includeRaw: false, timeZone: 'UTC' });
    expect(out).toMatchObject({ rows: 2, truncated: false, includesRaw: false });
    const [header, first] = out.csv.split('\r\n');
    expect(header).toBe(EVENT_CSV_COLUMNS.map((c) => `"${c}"`).join(','));
    expect(out.csv).not.toContain('raw ""line""');
    expect(first).toContain(`"'=HYPERLINK(""https://example.test"",""x"")"`);
    expect(first).toContain('"2026-10-27 10:00:00 UTC"');
  });

  it('includes raw lines when asked', () => {
    const out = eventsToCsv(events, [1], { includeRaw: true, timeZone: 'UTC' });
    expect(out.csv.split('\r\n')[0]).toContain('"raw_log_line"');
    expect(out.csv).toContain('"raw ""line"" with <script>"');
  });
});
