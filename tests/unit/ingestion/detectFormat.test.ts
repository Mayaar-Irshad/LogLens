import { describe, expect, it } from 'vitest';
import { detectFormat } from '../../../src/features/log-ingestion/detectFormat';
import { runPreflight, sampleLines } from '../../../src/features/log-ingestion/preflight';
import { fixture } from '../../helpers/ingest';

const lines = (path: string) => fixture(path).split('\n');

describe('detectFormat', () => {
  it('detects Linux auth logs', () => {
    const d = detectFormat(lines('auth/basic-auth.log'));
    expect(d.format).toBe('linux-auth');
    expect(d.confidence).toBeGreaterThan(0.8);
    expect(d.ambiguous).toBe(false);
  });

  it('detects access logs but marks Apache vs Nginx as ambiguous without hints', () => {
    const d = detectFormat(
      lines('web/access-combined.log').filter((l) => !l.includes('198.51.100.200')),
    );
    expect(d.format).toBe('apache');
    expect(d.ambiguous).toBe(true);
    expect(d.reason).toMatch(/Apache and Nginx/);
    expect(d.candidates.map((c) => c.format)).toEqual(expect.arrayContaining(['apache', 'nginx']));
  });

  it('uses the file name as a hint for Nginx', () => {
    const d = detectFormat(lines('web/access-combined.log'), 'nginx-access.log');
    expect(d.format).toBe('nginx');
    expect(d.ambiguous).toBe(false);
  });

  it('detects JSON Lines over CSV even though JSON contains commas', () => {
    const d = detectFormat(lines('structured/auth-events.jsonl'));
    expect(d.format).toBe('jsonl');
  });

  it('detects CSV with a header row', () => {
    const d = detectFormat(['user,ip,result', 'alice,192.0.2.1,ok', 'bob,192.0.2.2,fail']);
    expect(d.format).toBe('csv');
    expect(d.confidence).toBe(1);
  });

  it('down-weights CSV without a header-like first row', () => {
    const d = detectFormat(['1,2,3', '4,5,6']);
    expect(d.format).toBe('csv');
    expect(d.confidence).toBe(0.5);
  });

  it('returns no format for unsupported text', () => {
    const d = detectFormat(['hello world', 'this is prose', 'not a log']);
    expect(d.format).toBeNull();
    expect(d.ambiguous).toBe(true);
  });

  it('flags binary content as unsupported', () => {
    const d = detectFormat(['\u0000\u0001\u0002PK\u0003\u0004']);
    expect(d.format).toBeNull();
    expect(d.unsupportedReason).toMatch(/binary/);
  });

  it('handles an empty sample', () => {
    expect(detectFormat(['', '  ']).format).toBeNull();
  });

  it('marks a mixed sample as ambiguous', () => {
    const auth = lines('auth/basic-auth.log').slice(0, 5);
    const web = lines('web/access-combined.log').slice(0, 4);
    const d = detectFormat([...auth, ...web]);
    expect(d.ambiguous).toBe(true);
  });
});

describe('runPreflight', () => {
  it('drops a trailing partial line when the sample was truncated', () => {
    expect(sampleLines('a\nb\nc-partial', true)).toEqual(['a', 'b']);
    expect(sampleLines('a\nb', false)).toEqual(['a', 'b']);
  });

  it('discovers JSON keys, examples and a suggested mapping', () => {
    const p = runPreflight(fixture('structured/auth-events.jsonl'), { truncated: false });
    expect(p.detection.format).toBe('jsonl');
    expect(p.jsonl?.keys.map((k) => k.key)).toEqual(
      expect.arrayContaining(['@timestamp', 'source.ip', 'user.name']),
    );
    expect(p.jsonl?.suggestedMapping).toMatchObject({
      timestamp: '@timestamp',
      sourceIp: 'source.ip',
      username: 'user.name',
    });
    const ts = p.jsonl?.keys.find((k) => k.key === '@timestamp');
    expect(ts?.examples.length).toBeLessThanOrEqual(3);
  });

  it('discovers CSV columns and delimiter', () => {
    const p = runPreflight(fixture('structured/web-requests.csv'), { truncated: false });
    expect(p.detection.format).toBe('csv');
    expect(p.csv?.delimiter).toBe(',');
    expect(p.csv?.keys.map((k) => k.key)).toEqual([
      'time',
      'client_ip',
      'method',
      'url',
      'status',
      'user_agent',
      'note',
    ]);
    expect(p.csv?.suggestedMapping).toMatchObject({
      timestamp: 'time',
      sourceIp: 'client_ip',
      httpMethod: 'method',
      path: 'url',
      statusCode: 'status',
      userAgent: 'user_agent',
    });
  });

  it('does not sample structured fields for binary content', () => {
    const p = runPreflight('\u0000\u0000\u0000', { truncated: false });
    expect(p.detection.unsupportedReason).toBeDefined();
    expect(p.jsonl).toBeUndefined();
  });
});
