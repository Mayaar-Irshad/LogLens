import { describe, expect, it } from 'vitest';
import { runOnly } from '../../helpers/detection';
import { build, fail, MIN, ok, SEC, T0, times } from '../../helpers/events';

const ATTACKER = '203.0.113.50';

describe('AUTH-001 repeated failed logins from one IP', () => {
  it('triggers at exactly the threshold (10 in 5 minutes) and not at 9', () => {
    const ten = build(times(10, T0, 20 * SEC).map((t) => fail(t, ATTACKER, 'root')));
    const nine = build(times(9, T0, 20 * SEC).map((t) => fail(t, ATTACKER, 'root')));
    const hit = runOnly('AUTH-001', ten).detections;
    expect(hit).toHaveLength(1);
    expect(hit[0]).toMatchObject({
      ruleId: 'AUTH-001',
      severity: 'medium',
      matchedEventCount: 10,
      sourceIps: [ATTACKER],
      usernames: ['root'],
      start: T0,
      end: T0 + 9 * 20 * SEC,
      subjects: { ips: [ATTACKER], users: [] },
    });
    expect(hit[0]!.reason).toContain('threshold is 10');
    expect(runOnly('AUTH-001', nine).detections).toHaveLength(0);
  });

  it('respects the inclusive window boundary', () => {
    const exact = build(times(10, T0, (5 * MIN) / 9).map((t) => fail(t, ATTACKER, 'root')));
    expect(runOnly('AUTH-001', exact).detections).toHaveLength(1);
    const tooSlow = build(times(10, T0, (5 * MIN) / 9 + 1).map((t) => fail(t, ATTACKER, 'root')));
    expect(runOnly('AUTH-001', tooSlow).detections).toHaveLength(0);
  });

  it('escalates to high severity at five times the threshold', () => {
    const many = build(times(50, T0, SEC).map((t) => fail(t, ATTACKER, 'root')));
    expect(runOnly('AUTH-001', many).detections[0]).toMatchObject({
      severity: 'high',
      confidence: 'high',
    });
  });

  it('merges a sustained attack into one detection but separates distinct bursts', () => {
    const sustained = build(times(30, T0, 30 * SEC).map((t) => fail(t, ATTACKER, 'root')));
    const [d] = runOnly('AUTH-001', sustained).detections;
    expect(d?.matchedEventCount).toBe(30);
    const twoBursts = build([
      ...times(10, T0, SEC).map((t) => fail(t, ATTACKER, 'root')),
      ...times(10, T0 + 60 * MIN, SEC).map((t) => fail(t, ATTACKER, 'root')),
    ]);
    expect(runOnly('AUTH-001', twoBursts).detections).toHaveLength(2);
  });

  it('does not combine failures from different IPs', () => {
    const spread = build(times(20, T0, SEC).map((t, i) => fail(t, `198.51.100.${i % 4}`, 'root')));
    expect(runOnly('AUTH-001', spread).detections).toHaveLength(0);
  });

  it('ignores successes and events without timestamps, and says so', () => {
    const events = build([
      ...times(9, T0, SEC).map((t) => fail(t, ATTACKER, 'root')),
      ok(T0 + 20 * SEC, ATTACKER, 'root'),
      fail(undefined, ATTACKER, 'root'),
    ]);
    expect(runOnly('AUTH-001', events).detections).toHaveLength(0);
    const ten = build([
      ...times(10, T0, SEC).map((t) => fail(t, ATTACKER, 'root')),
      fail(undefined, ATTACKER, 'root'),
    ]);
    const [d] = runOnly('AUTH-001', ten).detections;
    expect(
      d?.limitations.some((l) => l.includes('1 authentication event without a valid timestamp')),
    ).toBe(true);
  });

  it('honours configured thresholds', () => {
    const five = build(times(5, T0, SEC).map((t) => fail(t, ATTACKER, 'root')));
    expect(runOnly('AUTH-001', five, { threshold: 5 }).detections).toHaveLength(1);
  });
});

describe('AUTH-002 repeated failures against one account', () => {
  it('triggers on failures from many IPs and lists them', () => {
    const events = build(times(8, T0, MIN).map((t, i) => fail(t, `198.51.100.${i}`, 'alice')));
    const [d] = runOnly('AUTH-002', events).detections;
    expect(d).toMatchObject({
      usernames: ['alice'],
      severity: 'medium',
      subjects: { users: ['alice'] },
    });
    expect(d?.sourceIps).toHaveLength(8);
    expect(runOnly('AUTH-002', events.slice(0, 7)).detections).toHaveLength(0);
  });

  it('lowers severity when the account does not exist', () => {
    const events = build(
      times(8, T0, MIN).map((t) => fail(t, ATTACKER, 'oracle', { invalidUser: true })),
    );
    expect(runOnly('AUTH-002', events).detections[0]?.severity).toBe('low');
  });
});

describe('AUTH-003 password spraying', () => {
  const users = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace'];

  it('triggers on five distinct accounts with one attempt each', () => {
    const events = build(users.slice(0, 5).map((u, i) => fail(T0 + i * MIN, ATTACKER, u)));
    const [d] = runOnly('AUTH-003', events).detections;
    expect(d).toMatchObject({ ruleId: 'AUTH-003', sourceIps: [ATTACKER] });
    expect(d?.usernames).toHaveLength(5);
    expect(runOnly('AUTH-003', events.slice(0, 4)).detections).toHaveLength(0);
  });

  it('leaves high-volume guessing (many attempts per account) to AUTH-001', () => {
    const events = build(
      users
        .slice(0, 5)
        .flatMap((u, i) => times(10, T0 + i * SEC * 30, SEC).map((t) => fail(t, ATTACKER, u))),
    );
    expect(runOnly('AUTH-003', events).detections).toHaveLength(0);
  });

  it('does not trigger when accounts are spread over a longer period than the window', () => {
    const events = build(users.slice(0, 5).map((u, i) => fail(T0 + i * 10 * MIN, ATTACKER, u)));
    expect(runOnly('AUTH-003', events).detections).toHaveLength(0);
  });
});

describe('AUTH-004 success after repeated failures', () => {
  it('flags a success preceded by failures from the same IP and account', () => {
    const events = build([
      ...times(3, T0, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 5 * MIN, ATTACKER, 'alice'),
    ]);
    const [d] = runOnly('AUTH-004', events).detections;
    expect(d).toMatchObject({
      severity: 'high',
      confidence: 'high',
      matchedEventCount: 4,
      subjects: { ips: [ATTACKER], users: ['alice'] },
      start: T0,
      end: T0 + 5 * MIN,
    });
    expect(d?.reason).toContain('not proof of compromise');
  });

  it('does not flag fewer failures than the minimum or failures outside the look-back', () => {
    const two = build([
      ...times(2, T0, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 5 * MIN, ATTACKER, 'alice'),
    ]);
    expect(runOnly('AUTH-004', two).detections).toHaveLength(0);
    const stale = build([
      ...times(3, T0, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 33 * MIN, ATTACKER, 'alice'),
    ]);
    expect(runOnly('AUTH-004', stale).detections).toHaveLength(0);
  });

  it('rates shared-IP-only correlation as medium', () => {
    const events = build([
      fail(T0, ATTACKER, 'bob'),
      fail(T0 + MIN, ATTACKER, 'carol'),
      fail(T0 + 2 * MIN, ATTACKER, 'dave'),
      ok(T0 + 3 * MIN, ATTACKER, 'alice'),
    ]);
    expect(runOnly('AUTH-004', events).detections[0]).toMatchObject({
      severity: 'medium',
      confidence: 'medium',
    });
  });

  it('merges repeated successes in the same episode', () => {
    const events = build([
      ...times(3, T0, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 5 * MIN, ATTACKER, 'alice'),
      ok(T0 + 6 * MIN, ATTACKER, 'alice'),
    ]);
    const res = runOnly('AUTH-004', events).detections;
    expect(res).toHaveLength(1);
    expect(res[0]?.matchedEventCount).toBe(5);
  });

  it('keeps separate episodes for the same IP and account', () => {
    const events = build([
      ...times(3, T0, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 5 * MIN, ATTACKER, 'alice'),
      ...times(3, T0 + 120 * MIN, MIN).map((t) => fail(t, ATTACKER, 'alice')),
      ok(T0 + 125 * MIN, ATTACKER, 'alice'),
    ]);
    expect(runOnly('AUTH-004', events).detections).toHaveLength(2);
  });

  it('is not applicable without successes', () => {
    const run = runOnly('AUTH-004', build([fail(T0, ATTACKER, 'a')]));
    expect(run.ruleRuns.find((r) => r.ruleId === 'AUTH-004')).toMatchObject({ evaluated: false });
  });
});

describe('AUTH-005 failures across many accounts', () => {
  const accounts = Array.from({ length: 10 }, (_, i) => `user${i}`);
  it('triggers for distributed failures and requires multiple sources', () => {
    const distributed = build(accounts.map((u, i) => fail(T0 + i * MIN, `198.51.100.${i % 3}`, u)));
    const [d] = runOnly('AUTH-005', distributed).detections;
    expect(d?.usernames).toHaveLength(10);
    expect(d?.sourceIps).toHaveLength(3);
    const single = build(accounts.map((u, i) => fail(T0 + i * MIN, ATTACKER, u)));
    expect(runOnly('AUTH-005', single).detections).toHaveLength(0);
    expect(runOnly('AUTH-005', distributed.slice(0, 9)).detections).toHaveLength(0);
  });
});

describe('AUTH-006 high login activity', () => {
  it('counts all outcomes and rates failure-heavy bursts higher', () => {
    const mixed = build(
      times(100, T0, SEC).map((t, i) =>
        i % 4 === 0 ? fail(t, ATTACKER, 'a') : ok(t, '192.0.2.1', 'b'),
      ),
    );
    expect(runOnly('AUTH-006', mixed).detections[0]).toMatchObject({
      severity: 'low',
      matchedEventCount: 100,
    });
    const failing = build(times(100, T0, SEC).map((t) => fail(t, ATTACKER, 'a')));
    expect(runOnly('AUTH-006', failing).detections[0]?.severity).toBe('medium');
    expect(runOnly('AUTH-006', failing.slice(0, 99)).detections).toHaveLength(0);
  });
});

describe('AUTH-007 non-existent accounts', () => {
  it('counts distinct invalid usernames per IP', () => {
    const names = ['admin', 'test', 'oracle', 'ubuntu', 'pi'];
    const events = build(
      names.flatMap((u, i) => [
        {
          category: 'authentication' as const,
          action: 'ssh_invalid_user',
          timestamp: T0 + i * MIN,
          sourceIp: ATTACKER,
          username: u,
          auth: { invalidUser: true },
        },
        fail(T0 + i * MIN + SEC, ATTACKER, u, { invalidUser: true }),
      ]),
    );
    const [d] = runOnly('AUTH-007', events).detections;
    expect(d).toMatchObject({ severity: 'low', confidence: 'high' });
    expect(d?.usernames).toEqual(names);
    expect(runOnly('AUTH-007', events.slice(0, 8)).detections).toHaveLength(0);
  });
});
