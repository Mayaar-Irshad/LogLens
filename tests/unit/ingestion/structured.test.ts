import { describe, expect, it } from 'vitest';
import {
  flattenObject,
  previewValue,
  mapStructuredRecord,
  suggestMapping,
  type FieldValue,
} from '../../../src/features/log-ingestion/normalization/structured';
import { parseJsonRecord } from '../../../src/features/log-ingestion/parsers/jsonl';
import {
  createCsvParser,
  detectDelimiter,
  normalizeHeader,
  splitCsvRecord,
} from '../../../src/features/log-ingestion/parsers/csv';
import { fixture, ingest, TEST_TIMESTAMPS, utc } from '../../helpers/ingest';

const JSON_MAPPING = {
  timestamp: '@timestamp',
  action: 'event.action',
  outcome: 'event.outcome',
  sourceIp: 'source.ip',
  username: 'user.name',
};

describe('JSON Lines parser', () => {
  const result = ingest(fixture('structured/auth-events.jsonl'), 'jsonl', {
    mapping: JSON_MAPPING,
  });

  it('accounts for every line', () => {
    expect(result.stats).toMatchObject({
      totalLines: 6,
      parsedRecords: 3,
      partialRecords: 1,
      rejectedRecords: 2,
      eventsCreated: 4,
    });
  });

  it('maps nested fields and infers authentication semantics', () => {
    expect(result.events[0]).toMatchObject({
      category: 'authentication',
      action: 'user_login',
      sourceIp: '203.0.113.5',
      username: 'alice',
      timestamp: utc(2026, 10, 27, 10),
      auth: { outcome: 'failure' },
      status: 'parsed',
    });
    expect(result.events[0]?.fields).toContainEqual(['service', 'vpn']);
    expect(result.events[1]?.auth?.outcome).toBe('success');
  });

  it('reports each invalid value on a partial record', () => {
    const partial = result.events[2]!;
    expect(partial.status).toBe('partial');
    expect(partial.issues).toEqual([
      'invalid timestamp: unrecognized timestamp format',
      'source IP is not a valid IP address',
    ]);
    expect(partial.username).toBe('bob');
  });

  it('rejects truncated JSON and non-object values without echoing content', () => {
    expect(result.rejected.map((r) => [r.line, r.reason])).toEqual([
      [4, 'invalid_json'],
      [5, 'not_an_object'],
    ]);
    expect(result.rejected[0]?.detail).not.toContain('carol');
  });

  it('accepts epoch timestamps and treats __proto__ keys as inert data', () => {
    const e = result.events[3]!;
    expect(e.timestamp).toBe(utc(2026, 10, 27, 10, 2));
    expect(e.category).toBe('session');
    expect(e.fields).toContainEqual(['__proto__.polluted', 'yes']);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('parseJsonRecord reports the kind of non-object value', () => {
    expect(parseJsonRecord('42')).toMatchObject({
      ok: false,
      reason: 'not_an_object',
      detail: 'expected a JSON object, found number',
    });
    expect(parseJsonRecord('null')).toMatchObject({
      ok: false,
      detail: 'expected a JSON object, found null',
    });
  });

  it('survives deeply nested input', () => {
    const deep = `${'{"a":'.repeat(5000)}1${'}'.repeat(5000)}`;
    const r = ingest(deep, 'jsonl', { limits: { maxLineLength: 100_000 } });
    expect(r.stats.parsedRecords + r.stats.rejectedRecords).toBe(1);
  });

  it('flattens the deepest line the limits allow without overflowing the stack', () => {
    // At the maximum line length (262,144 characters), far deeper than JSON.stringify survives.
    const objects = `{"o":${'{"a":'.repeat(40_000)}1${'}'.repeat(40_000)}}`;
    const arrays = `{"l":${'['.repeat(120_000)}1${']'.repeat(120_000)}}`;
    expect(flattenObject(JSON.parse(objects) as Record<string, unknown>).get('o.a.a.a')).toBe(
      '{"a":{"a":{"a":{…}}}}',
    );
    expect(flattenObject(JSON.parse(arrays) as Record<string, unknown>).get('l')).toBe('[[[[…]]]]');
    const r = ingest(`${objects}\n${arrays}`, 'jsonl', { limits: { maxLineLength: 262_144 } });
    expect(r.stats.parsedRecords + r.stats.rejectedRecords).toBe(2);
  });

  it('skips comment lines', () => {
    const r = ingest('# exported\n{"a":1}', 'jsonl');
    expect(r.stats).toMatchObject({ skippedLines: 1, parsedRecords: 1 });
  });
});

describe('CSV parser', () => {
  const mapping = {
    timestamp: 'time',
    sourceIp: 'client_ip',
    httpMethod: 'method',
    path: 'url',
    statusCode: 'status',
    userAgent: 'user_agent',
  };
  const result = ingest(fixture('structured/web-requests.csv'), 'csv', { mapping });
  const at = (line: number) => result.events.find((e) => e.line === line)!;

  it('accounts for every line, including a quoted multi-line record', () => {
    expect(result.stats).toMatchObject({
      totalLines: 9,
      skippedLines: 1,
      parsedRecords: 4,
      partialRecords: 2,
      rejectedRecords: 1,
      eventsCreated: 6,
    });
  });

  it('maps columns into web events', () => {
    expect(at(2)).toMatchObject({
      category: 'web',
      sourceIp: '192.0.2.20',
      timestamp: utc(2026, 10, 27, 10),
      http: { method: 'GET', path: '/index.html', status: 200, userAgent: 'Mozilla/5.0' },
    });
    expect(at(2).fields).toContainEqual(['note', 'ok']);
  });

  it('handles quoted delimiters and absolute URLs', () => {
    expect(at(3).http).toMatchObject({
      path: '/login',
      query: 'next=/admin',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    });
    expect(at(3).fields).toContainEqual(['note', 'contains, comma']);
  });

  it('assembles quoted newlines into one record that starts at the first line', () => {
    expect(at(4).fields).toContainEqual(['note', 'multi\nline note'.replace('\n', '\n')]);
    expect(at(4).raw).toContain('\n');
  });

  it('flags invalid values and short rows', () => {
    expect(at(6).issues).toEqual(['invalid HTTP status code']);
    expect(at(7).issues?.[0]).toBe('record has 3 of 7 columns');
  });

  it('rejects empty records', () => {
    expect(result.rejected).toEqual([
      expect.objectContaining({ line: 8, reason: 'csv_empty_record' }),
    ]);
  });

  it('keeps spreadsheet-formula-like values as plain data', () => {
    expect(at(9).http?.userAgent).toBe('=HYPERLINK("http://example.test")');
  });

  it('rejects an unterminated quote at end of input', () => {
    const r = ingest('a,b\n1,"open\nstill open', 'csv');
    expect(r.rejected[0]).toMatchObject({ line: 2, reason: 'csv_unterminated_quote' });
  });

  it('gives up on runaway quoted fields after the line budget', () => {
    const parser = createCsvParser({
      ...TEST_TIMESTAMPS,
      mapping: {},
      maxRecordLength: 10_000,
      maxRecordLines: 3,
    });
    parser.push('a,b', 1);
    expect(parser.push('1,"x', 2)).toEqual([]);
    expect(parser.isBuffering()).toBe(true);
    expect(parser.push('y', 3)).toEqual([]);
    expect(parser.push('z', 4)[0]).toMatchObject({
      type: 'reject',
      line: 2,
      reason: 'csv_unterminated_quote',
    });
    expect(parser.isBuffering()).toBe(false);
  });

  it('keeps blank lines that are inside a quoted field', () => {
    const r = ingest('a,b\n1,"first\n\nthird"\n2,x', 'csv');
    expect(r.stats).toMatchObject({ parsedRecords: 2, blankLines: 0 });
    expect(r.events[0]?.fields).toContainEqual(['b', 'first\n\nthird']);
  });

  it('honours an Excel sep= directive and detects delimiters', () => {
    const r = ingest('sep=;\nuser;ip\nalice;192.0.2.1', 'csv', {
      mapping: { username: 'user', sourceIp: 'ip' },
    });
    expect(r.events[0]).toMatchObject({ username: 'alice', sourceIp: '192.0.2.1' });
    expect(detectDelimiter('a\tb\tc')).toBe('\t');
    expect(detectDelimiter('"a;b",c')).toBe(',');
    expect(detectDelimiter('single')).toBe(',');
  });

  it('splits RFC 4180 records', () => {
    expect(splitCsvRecord('a,"b,c","d""e",', ',')).toEqual(['a', 'b,c', 'd"e', '']);
    expect(splitCsvRecord('"unterminated', ',')).toBeNull();
    expect(splitCsvRecord('x"y",z', ',')).toEqual(['x"y"', 'z']);
  });

  it('normalizes and de-duplicates header names', () => {
    expect(normalizeHeader(['\ufefftime', 'ip', 'ip', ''])).toEqual([
      'time',
      'ip',
      'ip_2',
      'column_4',
    ]);
  });
});

describe('field mapping suggestions', () => {
  const values = (map: Record<string, FieldValue[]>) => (key: string) => map[key] ?? [];

  it('suggests ECS-style nested keys', () => {
    const sample = {
      '@timestamp': ['2026-10-27T10:00:00Z'],
      'source.ip': ['192.0.2.1'],
      'user.name': ['alice'],
      'event.outcome': ['failure'],
      'event.action': ['login'],
      'http.response.status_code': [200],
    };
    expect(suggestMapping(Object.keys(sample), values(sample))).toEqual({
      timestamp: '@timestamp',
      sourceIp: 'source.ip',
      username: 'user.name',
      statusCode: 'http.response.status_code',
      outcome: 'event.outcome',
      action: 'event.action',
    });
  });

  it('uses example values to disambiguate "status"', () => {
    const textual = { time: ['2026-10-27 10:00:00'], status: ['success', 'failure'] };
    expect(suggestMapping(Object.keys(textual), values(textual))).toEqual({
      timestamp: 'time',
      outcome: 'status',
    });
    const numeric = { time: ['2026-10-27 10:00:00'], status: [200, 404] };
    expect(suggestMapping(Object.keys(numeric), values(numeric))).toEqual({
      timestamp: 'time',
      statusCode: 'status',
    });
  });

  it('does not map keys whose values fail validation', () => {
    const bad = { time: ['soon'], ip: ['not-an-ip'] };
    expect(suggestMapping(Object.keys(bad), values(bad))).toEqual({});
  });
});

describe('mapStructuredRecord', () => {
  it('reports a mapped but missing timestamp', () => {
    const d = mapStructuredRecord(
      new Map([['user', 'a']]),
      { timestamp: 'ts', username: 'user' },
      TEST_TIMESTAMPS,
    );
    expect(d.issues).toEqual(['timestamp field "ts" is missing']);
  });

  it('infers outcome from event text when no outcome field exists', () => {
    const d = mapStructuredRecord(
      new Map([['type', 'LOGIN_FAILED']]),
      { eventType: 'type' },
      TEST_TIMESTAMPS,
    );
    expect(d).toMatchObject({
      category: 'authentication',
      action: 'login_failed',
      auth: { outcome: 'failure' },
    });
  });

  it('flattens bounded nested structures', () => {
    const flat = flattenObject({
      a: { b: { c: 1 } },
      list: [1, 2, 'x'],
      objs: [{ k: 1 }],
      n: null,
    });
    expect([...flat]).toEqual([
      ['a.b.c', 1],
      ['list', '1, 2, x'],
      ['objs', '[{"k":1}]'],
    ]);
  });

  it('previews nested values like JSON, bounded in depth and length', () => {
    expect(previewValue([{ k: 1, s: 'x"y' }, null, true])).toBe('[{"k":1,"s":"x\\"y"},null,true]');
    expect(previewValue({ a: { b: { c: { d: 1 } } } })).toBe('{"a":{"b":{"c":{…}}}}');
    const wide = previewValue(
      Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`k${i}`, i])),
    );
    expect(wide.length).toBeLessThan(600);
    expect(wide.endsWith(',…}')).toBe(true);
  });

  it('validates HTTP methods', () => {
    const d = mapStructuredRecord(new Map([['m', 'G E T']]), { httpMethod: 'm' }, TEST_TIMESTAMPS);
    expect(d.issues).toEqual(['invalid HTTP method']);
  });
});
