import { describe, expect, it } from 'vitest';
import {
  parseRequestLine,
  tokenizeTrailing,
  unescapeLogString,
} from '../../../src/features/log-ingestion/parsers/accessLog';
import { fixture, ingest, utc } from '../../helpers/ingest';

describe('Apache / Nginx access log parser — fixture', () => {
  const result = ingest(fixture('web/access-combined.log'), 'nginx');
  const at = (line: number) => result.events.find((e) => e.line === line)!;

  it('accounts for every line', () => {
    expect(result.stats).toMatchObject({
      totalLines: 12,
      parsedRecords: 8,
      partialRecords: 3,
      rejectedRecords: 1,
      eventsCreated: 11,
    });
    expect(result.format).toBe('nginx');
  });

  it('parses combined format fields', () => {
    expect(at(1)).toMatchObject({
      category: 'web',
      action: 'http_request',
      sourceIp: '192.0.2.10',
      timestamp: utc(2026, 10, 27, 10, 0, 0),
      status: 'parsed',
      http: {
        method: 'GET',
        path: '/index.html',
        protocol: 'HTTP/1.1',
        status: 200,
        bytes: 5120,
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
      },
    });
    expect(at(1).http?.referrer).toBeUndefined();
    expect(at(2).http?.referrer).toBe('https://example.test/');
  });

  it('separates the query string, keeps the authenticated user and applies the offset', () => {
    expect(at(3)).toMatchObject({
      username: 'jdoe',
      timestamp: utc(2026, 10, 27, 10, 0, 2),
      http: { method: 'POST', path: '/login', query: 'next=%2Fadmin', status: 401 },
    });
  });

  it('marks malformed request lines (e.g. TLS handshakes on a plain-HTTP port) as partial', () => {
    const e = at(5);
    expect(e.status).toBe('partial');
    expect(e.issues).toContain('malformed request line');
    expect(e.http?.method).toBeUndefined();
    expect(e.http?.status).toBe(400);
    expect(e.fields?.find(([k]) => k === 'request')?.[1]).toContain('\\x16\\x03');
  });

  it('treats an empty "-" request as valid (e.g. 408 timeouts)', () => {
    expect(at(6)).toMatchObject({ status: 'parsed', http: { status: 408, bytes: 0 } });
  });

  it('unescapes quotes inside the request line', () => {
    expect(at(7).http).toMatchObject({ path: '/search', query: 'q="quoted"', status: 500 });
  });

  it('parses Common Log Format and canonicalizes IPv6 clients', () => {
    expect(at(8)).toMatchObject({
      sourceIp: '2001:db8::7',
      status: 'parsed',
      http: { status: 200 },
    });
    expect(at(8).http?.userAgent).toBeUndefined();
  });

  it('keeps non-IP clients and bad timestamps as partial records', () => {
    expect(at(9).status).toBe('partial');
    expect(at(9).fields).toContainEqual(['client_host', 'not-an-ip']);
    expect(at(10).status).toBe('partial');
    expect(at(10).timestamp).toBeUndefined();
  });

  it('keeps trailing Nginx fields', () => {
    expect(at(12).fields).toContainEqual(['extra_1', '198.51.100.200']);
    expect(result.stats.warnings.map((w) => w.code)).toContain('extra_fields');
  });

  it('rejects unstructured lines', () => {
    expect(result.rejected.map((r) => r.line)).toEqual([11]);
  });
});

describe('access log helpers', () => {
  it('parses request lines', () => {
    expect(parseRequestLine('GET /a?b=c HTTP/1.0')).toEqual({
      method: 'GET',
      path: '/a',
      query: 'b=c',
      protocol: 'HTTP/1.0',
      malformed: false,
    });
    expect(parseRequestLine('PROPFIND /webdav')).toEqual({
      method: 'PROPFIND',
      path: '/webdav',
      malformed: false,
    });
    expect(parseRequestLine('-')).toEqual({ malformed: false });
    expect(parseRequestLine('GET')).toEqual({ malformed: true });
    // Unencoded spaces (common in attack payloads) stay in the target instead of hiding it.
    expect(parseRequestLine('GET /a b HTTP/1.1')).toEqual({
      method: 'GET',
      path: '/a b',
      protocol: 'HTTP/1.1',
      malformed: false,
    });
  });

  it('unescapes only quote and backslash escapes', () => {
    expect(unescapeLogString('a\\"b\\\\c\\x41')).toBe('a"b\\c\\x41');
  });

  it('tokenizes trailing quoted and bare fields', () => {
    expect(tokenizeTrailing(' "ref" "ua \\"x\\"" 0.123 "xff"')).toEqual([
      { quoted: true, value: 'ref' },
      { quoted: true, value: 'ua "x"' },
      { quoted: false, value: '0.123' },
      { quoted: true, value: 'xff' },
    ]);
  });

  it('accepts an Apache vhost prefix', () => {
    const [e] = ingest(
      'www.example.test:443 192.0.2.1 - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
      'apache',
    ).events;
    expect(e).toMatchObject({ sourceIp: '192.0.2.1', format: 'apache' });
    expect(e?.fields).toContainEqual(['vhost', 'www.example.test:443']);
  });

  it('stores XSS-like strings as inert text', () => {
    const payload = '<script>alert(1)</script>';
    const [e] = ingest(
      `192.0.2.1 - - [27/Oct/2026:10:00:00 +0000] "GET /${payload} HTTP/1.1" 404 1 "-" "${payload}"`,
      'apache',
    ).events;
    expect(e?.http?.path).toBe(`/${payload}`);
    expect(e?.http?.userAgent).toBe(payload);
  });
});
