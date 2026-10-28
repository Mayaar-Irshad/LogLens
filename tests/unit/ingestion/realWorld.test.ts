import { describe, expect, it } from 'vitest';
import { computeMetrics } from '../../../src/features/analytics/aggregate';
import { filterEventIds } from '../../../src/features/analytics/filterEvents';
import { detectFormat } from '../../../src/features/log-ingestion/detectFormat';
import { normalizeIp } from '../../../src/features/log-ingestion/normalization/ip';
import { inferOutcomeFromText } from '../../../src/features/log-ingestion/normalization/outcome';
import { classifyAuthMessage } from '../../../src/features/log-ingestion/parsers/linuxAuth';
import { runOnly } from '../../helpers/detection';
import { build, ok, T0 } from '../../helpers/events';
import { ingest } from '../../helpers/ingest';

/** Real-world input variants found by an independent accuracy review. */

describe('syslog variants', () => {
  it('accepts a priority prefix and space-separated ISO timestamps', () => {
    const r = ingest(
      [
        '<38>Oct 27 10:00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2',
        '2026-10-27 10:00:01 h sshd[1]: Failed password for root from 203.0.113.5 port 23 ssh2',
      ].join('\n'),
      'linux-auth',
    );
    expect(r.stats).toMatchObject({ parsedRecords: 2, rejectedRecords: 0 });
    expect(r.events[0]?.raw.startsWith('<38>')).toBe(true);
    expect(
      detectFormat([
        '<38>Oct 27 10:00:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2',
      ]).format,
    ).toBe('linux-auth');
  });

  it('skips journalctl boot markers instead of rejecting them', () => {
    const r = ingest(
      '-- Boot 3f2a9c1e8b7d4c6a --\nOct 27 10:00:00 h sshd[1]: Server listening on 0.0.0.0 port 22.',
      'linux-auth',
    );
    expect(r.stats).toMatchObject({ skippedLines: 1, rejectedRecords: 0 });
  });

  it('expands "last message repeated N times" from sysklogd and BusyBox', () => {
    const r = ingest(
      [
        'Oct 27 10:00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2',
        'Oct 27 10:00:30 h last message repeated 20 times',
      ].join('\n'),
      'linux-auth',
    );
    expect(r.events).toHaveLength(21);
    expect(r.events[20]).toMatchObject({ sourceIp: '203.0.113.5', repeat: { index: 20, of: 20 } });
    expect(runOnly('AUTH-001', r.events).detections).toHaveLength(1);
  });

  it('parses Dropbear authentication messages', () => {
    expect(
      classifyAuthMessage('dropbear', "Bad password attempt for 'root' from 203.0.113.5:51000"),
    ).toMatchObject({
      action: 'ssh_login_failed',
      username: 'root',
      ip: '203.0.113.5',
      auth: { outcome: 'failure', port: 51000 },
    });
    expect(
      classifyAuthMessage(
        'dropbear',
        "Login attempt for nonexistent user 'pi' from 203.0.113.5:4000",
      ),
    ).toMatchObject({
      auth: { outcome: 'failure', invalidUser: true },
    });
    expect(
      classifyAuthMessage('dropbear', "Password auth succeeded for 'admin' from 192.0.2.1:2222"),
    ).toMatchObject({
      action: 'ssh_login_success',
      auth: { outcome: 'success' },
    });
  });

  it('does not count rejected public keys as failed credential attempts', () => {
    const c = classifyAuthMessage(
      'sshd',
      'Failed publickey for alice from 198.51.100.10 port 50000 ssh2: RSA SHA256:x',
    );
    expect(c.action).toBe('ssh_key_rejected');
    expect(c.auth?.outcome).toBeUndefined();
  });

  it('treats sudo -i and su - PAM failures as privilege events', () => {
    expect(
      classifyAuthMessage(
        'sudo',
        'pam_unix(sudo-i:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob',
      ).category,
    ).toBe('privilege');
    expect(
      classifyAuthMessage(
        'su',
        'pam_unix(su-l:auth): authentication failure; logname=bob uid=1000 euid=0 tty=pts/1 ruser=bob rhost=  user=bob',
      ).category,
    ).toBe('privilege');
  });
});

describe('addresses and outcomes', () => {
  it('accepts IP addresses that carry a port', () => {
    expect(normalizeIp('203.0.113.5:51234')).toBe('203.0.113.5');
    expect(normalizeIp('[2001:db8::1]:443')).toBe('2001:db8::1');
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
  });

  it.each(['login_unsuccessful', 'access_not_granted', 'login_not_allowed', 'auth.not-authorized'])(
    'reads %s as a failure',
    (text) => {
      expect(inferOutcomeFromText(text)).toBe('failure');
    },
  );
});

describe('CSV quoting', () => {
  it('does not let a stray quote inside an unquoted value swallow later records', () => {
    const rows = Array.from(
      { length: 60 },
      (_, i) => `2026-10-27T10:00:${String(i % 60).padStart(2, '0')}Z,192.0.2.${i % 200},/p${i}`,
    );
    const text = [
      'time,ip,path',
      '2026-10-27T09:59:59Z,192.0.2.1,/search?q=27" monitor',
      ...rows,
    ].join('\n');
    const r = ingest(text, 'csv', { mapping: { timestamp: 'time', sourceIp: 'ip', path: 'path' } });
    expect(r.stats).toMatchObject({ rejectedRecords: 0, eventsCreated: 61 });
    expect(r.events[0]?.http?.path).toBe('/search');
  });
});

describe('filters and counters agree', () => {
  it('uses one definition of an authentication outcome', () => {
    const events = build([
      {
        category: 'privilege',
        action: 'sudo_auth_failure',
        timestamp: T0,
        username: 'bob',
        auth: { outcome: 'failure' },
      },
      {
        category: 'privilege',
        action: 'su_failed',
        timestamp: T0,
        username: 'eve',
        auth: { outcome: 'failure' },
      },
      {
        category: 'authentication',
        action: 'ssh_login_failed',
        timestamp: T0,
        username: 'root',
        auth: { outcome: 'failure' },
      },
      ok(T0, '192.0.2.1', 'alice'),
    ]);
    const ids = filterEventIds(events, { authOutcomes: ['failure'] });
    expect(ids).toEqual([2]);
    expect(computeMetrics(events, ids, { timeZone: 'UTC' }).auth.failure).toBe(ids.length);
  });
});
