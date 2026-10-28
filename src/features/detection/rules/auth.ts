import type { Confidence, Severity } from '../../../types/detection';
import type { NormalizedEvent } from '../../../types/events';
import {
  isoUtc,
  listPreview,
  minutes,
  plural,
  representative,
  unique,
  uniqueIds,
} from '../engine/context';
import type { DetectionContext, Finding, RuleDefinition } from '../engine/types';
import {
  findBursts,
  findDistinctBursts,
  groupBy,
  lowerBound,
  topCounts,
  type TimedRef,
} from '../engine/windows';
import { countParam, SEVERITY_ESCALATION_NOTE, windowParam } from './params';

const MINUTE = 60_000;

const refs = (events: NormalizedEvent[]): TimedRef[] =>
  events.map((e) => ({ t: e.timestamp!, id: e.id }));
const pick = (ctx: DetectionContext, ids: number[]): NormalizedEvent[] =>
  ids.map((id) => ctx.events[id]!);
const topList = (values: Array<string | undefined>, n = 5): string =>
  topCounts(values, n)
    .map((c) => `${c.key} (${c.count})`)
    .join(', ') || 'none';

const durationText = (start: number, end: number): string => {
  const sec = Math.round((end - start) / 1000);
  if (sec < 120) return `${sec}s`;
  return `${Math.round(sec / 60)} min`;
};

const UNTIMED_NOTE = (ctx: DetectionContext): string[] =>
  ctx.untimed.auth > 0
    ? [
        `${plural(ctx.untimed.auth, 'authentication event')} without a valid timestamp could not be placed in a time window and were excluded.`,
      ]
    : [];

const COMMON_AUTH_LIMITATIONS = [
  'Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.',
  'A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.',
  SEVERITY_ESCALATION_NOTE,
];

export const AUTH_001: RuleDefinition = {
  id: 'AUTH-001',
  name: 'Repeated failed logins from one source IP',
  category: 'authentication',
  scope: 'ip',
  description:
    'Many failed authentication attempts from a single source address within a short window. This pattern is consistent with password guessing, but also with misconfigured clients.',
  requires: 'Authentication events with an outcome, a source IP and a timestamp.',
  params: [
    countParam(
      'threshold',
      'Failed attempts',
      'Minimum failed attempts from one IP within the window.',
      10,
      2,
    ),
    windowParam(5),
  ],
  recommendations: [
    'Check whether any login from this IP succeeded during or after the burst (see AUTH-004 and the event explorer).',
    'Review which accounts were targeted; prioritise privileged and real (existing) accounts.',
    'Confirm whether the address belongs to your organisation, a partner, or a known scanner before blocking.',
    'Consider rate limiting, fail2ban-style blocking, disabling password authentication, or enforcing MFA.',
  ],
  limitations: COMMON_AUTH_LIMITATIONS,
  falsePositives: [
    'Automation or scripts using an expired password.',
    'A user repeatedly mistyping a password.',
    'Shared egress IPs (corporate NAT, VPN) aggregating many users.',
  ],
  mitre: [{ id: 'T1110.001', name: 'Brute Force: Password Guessing' }],
  applicable: (ctx) =>
    ctx.authFailures.some((e) => e.sourceIp)
      ? null
      : 'No timestamped authentication failures with a source IP.',
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(ctx.authFailures, (e) => e.sourceIp)) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const users = unique(evs.map((e) => e.username));
        const invalid = evs.filter((e) => e.auth?.invalidUser).length;
        const severity: Severity = b.count >= threshold * 5 ? 'high' : 'medium';
        const confidence: Confidence = b.peak >= threshold * 2 ? 'high' : 'medium';
        findings.push({
          key: ip,
          severity,
          confidence,
          title: `Repeated failed logins from ${ip}`,
          reason: `${plural(b.count, 'failed login')} from ${ip} between ${isoUtc(b.start)} and ${isoUtc(b.end)} (${durationText(b.start, b.end)}). Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.`,
          condition: `failed authentication attempts from the same source IP ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: 'Failed attempts', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: users,
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Failed attempts in episode', value: String(b.count) },
            { label: 'Peak within window', value: `${b.peak} in ${minutes(window)}` },
            {
              label: 'Accounts targeted',
              value: `${users.length}: ${topList(evs.map((e) => e.username))}`,
            },
            { label: 'Attempts against non-existent accounts', value: String(invalid) },
            { label: 'Methods', value: topList(evs.map((e) => e.auth?.method)) },
          ],
          extraLimitations: UNTIMED_NOTE(ctx),
        });
      }
    }
    return findings;
  },
};

export const AUTH_002: RuleDefinition = {
  id: 'AUTH-002',
  name: 'Repeated failed logins against one account',
  category: 'authentication',
  scope: 'user',
  description:
    'Many failed authentication attempts against a single username within a short window, from one or more source addresses.',
  requires: 'Authentication events with an outcome, a username and a timestamp.',
  params: [
    countParam(
      'threshold',
      'Failed attempts',
      'Minimum failed attempts against one account within the window.',
      8,
      2,
    ),
    windowParam(10),
  ],
  recommendations: [
    'Confirm with the account owner whether they were attempting to log in.',
    'Check for a later successful login for this account (AUTH-004) and review activity after it.',
    'If the attempts come from many IPs, consider a distributed guessing campaign and enable account lockout or MFA.',
    'Check whether the account is privileged or a service account with a stale credential.',
  ],
  limitations: [
    ...COMMON_AUTH_LIMITATIONS,
    'Attempts against accounts that do not exist on the host are lower risk; see the evidence for whether the account was reported as invalid.',
  ],
  falsePositives: [
    'Service accounts or cron jobs using an outdated password.',
    'Users with a cached old password on a mobile device or mail client.',
  ],
  mitre: [{ id: 'T1110.001', name: 'Brute Force: Password Guessing' }],
  applicable: (ctx) =>
    ctx.authFailures.some((e) => e.username)
      ? null
      : 'No timestamped authentication failures with a username.',
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const findings: Finding[] = [];
    for (const [user, events] of groupBy(ctx.authFailures, (e) => e.username)) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const ips = unique(evs.map((e) => e.sourceIp));
        const allInvalid = evs.every((e) => e.auth?.invalidUser);
        let severity: Severity = b.count >= threshold * 5 ? 'high' : 'medium';
        if (allInvalid) severity = 'low';
        findings.push({
          key: user,
          severity,
          confidence: b.peak >= threshold * 2 ? 'high' : 'medium',
          title: `Repeated failed logins for account "${user}"`,
          reason: `${plural(b.count, 'failed login')} against "${user}" from ${plural(ips.length, 'source IP')} between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.${allInvalid ? ' The service reported this account as non-existent.' : ''}`,
          condition: `failed authentication attempts against the same username ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: 'Failed attempts', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: ips,
          usernames: [user],
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Failed attempts in episode', value: String(b.count) },
            { label: 'Source IPs', value: `${ips.length}: ${topList(evs.map((e) => e.sourceIp))}` },
            { label: 'Account reported as non-existent', value: allInvalid ? 'yes' : 'no' },
          ],
          extraLimitations: UNTIMED_NOTE(ctx),
        });
      }
    }
    return findings;
  },
};

export const AUTH_003: RuleDefinition = {
  id: 'AUTH-003',
  name: 'Possible password spraying from one source IP',
  category: 'authentication',
  scope: 'ip',
  description:
    'One source address fails to authenticate as many different usernames within a window, with few attempts per account. Password spraying tries a small number of common passwords across many accounts to avoid lockouts.',
  requires: 'Authentication events with an outcome, source IP, username and timestamp.',
  params: [
    countParam(
      'minUsernames',
      'Distinct usernames',
      'Minimum distinct usernames with failures from one IP within the window.',
      5,
      2,
      10_000,
      'accounts',
    ),
    windowParam(15),
    countParam(
      'maxAttemptsPerUser',
      'Max average attempts per account',
      'Spraying uses few attempts per account. Episodes above this average are left to AUTH-001.',
      3,
      1,
      1000,
      'attempts',
    ),
  ],
  recommendations: [
    'Check whether any of the targeted accounts later logged in successfully, from this or any IP.',
    'Compare the targeted usernames with your real account list; real names indicate prior reconnaissance.',
    'Enforce MFA and check password policy for the targeted accounts.',
  ],
  limitations: [
    ...COMMON_AUTH_LIMITATIONS,
    'Slow sprays spread over hours or days will not be detected with short windows; increase the window to look for them.',
  ],
  falsePositives: [
    'A shared jump host or NAT gateway where several users mistype passwords.',
    'Vulnerability scanners or penetration tests that are authorised.',
  ],
  mitre: [{ id: 'T1110.003', name: 'Brute Force: Password Spraying' }],
  applicable: (ctx) =>
    ctx.authFailures.some((e) => e.sourceIp && e.username)
      ? null
      : 'No authentication failures with both a source IP and a username.',
  evaluate(ctx, p) {
    const minUsers = p.minUsernames!;
    const window = p.windowMinutes!;
    const maxAvg = p.maxAttemptsPerUser!;
    const findings: Finding[] = [];
    const usable = ctx.authFailures.filter((e) => e.username);
    for (const [ip, events] of groupBy(usable, (e) => e.sourceIp)) {
      const items = events.map((e) => ({ t: e.timestamp!, id: e.id, key: e.username! }));
      for (const b of findDistinctBursts(items, window * MINUTE, minUsers)) {
        const evs = pick(ctx, b.ids);
        const users = unique(evs.map((e) => e.username));
        const avg = b.count / users.length;
        if (avg > maxAvg) continue;
        const invalidShare = evs.filter((e) => e.auth?.invalidUser).length / evs.length;
        findings.push({
          key: ip,
          severity: users.length >= minUsers * 3 ? 'high' : 'medium',
          confidence: b.peak >= minUsers * 2 ? 'high' : 'medium',
          title: `Possible password spraying from ${ip}`,
          reason: `${ip} failed to authenticate as ${plural(users.length, 'different account')} (${plural(b.count, 'attempt')}, ${avg.toFixed(1)} per account) between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} distinct accounts within ${minutes(window)}; threshold is ${minUsers}.`,
          condition: `distinct usernames with failed attempts from the same IP ≥ ${minUsers} within ${minutes(window)}, average attempts per account ≤ ${maxAvg}`,
          thresholds: [
            { name: 'Distinct usernames', value: minUsers, unit: 'accounts' },
            { name: 'Window', value: window, unit: 'minutes' },
            { name: 'Max average attempts per account', value: maxAvg },
          ],
          metric: b.peak,
          primaryThreshold: minUsers,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: users,
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Accounts targeted', value: `${users.length}: ${listPreview(users, 8)}` },
            { label: 'Average attempts per account', value: avg.toFixed(1) },
            {
              label: 'Share against non-existent accounts',
              value: `${Math.round(invalidShare * 100)}%`,
            },
          ],
          extraLimitations: UNTIMED_NOTE(ctx),
        });
      }
    }
    return findings;
  },
};

export const AUTH_004: RuleDefinition = {
  id: 'AUTH-004',
  name: 'Successful login after repeated failures',
  category: 'authentication',
  scope: 'ip-user',
  description:
    'A successful authentication preceded by several failures from the same source IP or against the same account. This can indicate a guessed password, or simply a user who eventually typed it correctly.',
  requires: 'Authentication events with success and failure outcomes, and timestamps.',
  params: [
    countParam(
      'minFailures',
      'Prior failures',
      'Minimum failures before the success within the look-back window.',
      3,
      1,
      10_000,
    ),
    windowParam(30),
  ],
  recommendations: [
    'Treat as a priority lead: contact the account owner to confirm the login was legitimate.',
    'Review all activity in the session that followed (commands, sudo use, file changes, new keys).',
    'If not legitimate: disable the account, rotate credentials and keys, and look for persistence (authorized_keys, cron, new users).',
    'Check whether the same IP authenticated to other hosts.',
  ],
  limitations: [
    'Correlation is by shared source IP or shared username only; the logs cannot prove the same person made both attempts.',
    'Successful public-key logins after password failures may be unrelated (for example a user falling back to a key).',
    ...COMMON_AUTH_LIMITATIONS,
  ],
  falsePositives: [
    'Users who mistype a password a few times before succeeding.',
    'Password managers or clients retrying stale credentials before using new ones.',
  ],
  mitre: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1078', name: 'Valid Accounts' },
  ],
  applicable: (ctx) => {
    const hasSuccess = ctx.authAttempts.some((e) => e.auth?.outcome === 'success');
    return hasSuccess && ctx.authFailures.length > 0
      ? null
      : 'Needs both successful and failed timestamped authentication events.';
  },
  evaluate(ctx, p) {
    const minFailures = p.minFailures!;
    const window = p.windowMinutes!;
    const lookback = window * MINUTE;
    const byIp = groupBy(ctx.authFailures, (e) => e.sourceIp);
    const byUser = groupBy(ctx.authFailures, (e) => e.username);
    const ipRefs = new Map([...byIp].map(([k, v]) => [k, refs(v)]));
    const userRefs = new Map([...byUser].map(([k, v]) => [k, refs(v)]));
    /** Failures before the success within the look-back, including same-second failures logged earlier. */
    const before = (
      list: TimedRef[] | undefined,
      success: NormalizedEvent,
      after: number,
    ): number[] => {
      if (!list) return [];
      const t = success.timestamp!;
      const out: number[] = [];
      for (let i = lowerBound(list, Math.max(t - lookback, after)); i < list.length; i++) {
        const r = list[i]!;
        if (r.t > t || (r.t === t && r.id > success.id)) break;
        if (r.t > after || after === -Infinity) out.push(r.id);
      }
      return out;
    };

    type Open = Finding & { lastSuccess: number };
    const all: Open[] = [];
    const open = new Map<string, Open>();
    for (const success of ctx.authAttempts) {
      if (success.auth?.outcome !== 'success') continue;
      const t = success.timestamp!;
      const ip = success.sourceIp;
      const user = success.username;
      const key = `${ip ?? '?'}|${user ?? '?'}`;
      const existing = open.get(key);
      const continuing = existing !== undefined && t - existing.lastSuccess <= lookback;
      // Within an open episode, only failures after the previous success are new evidence.
      const after = continuing ? existing.lastSuccess : -Infinity;
      const fromIp = ip ? before(ipRefs.get(ip), success, after) : [];
      const fromUser = user ? before(userRefs.get(user), success, after) : [];
      const failures = uniqueIds([...fromIp, ...fromUser]);
      if (failures.length < minFailures) {
        if (continuing) {
          existing.eventIds = uniqueIds([...existing.eventIds, success.id]);
          existing.end = t;
          existing.lastSuccess = t;
        }
        continue;
      }
      const failEvents = pick(ctx, failures);
      const samePair = failEvents.filter((e) => e.sourceIp === ip && e.username === user).length;
      const sameIp = fromIp.length;
      // How strongly the failures are tied to this login decides the severity and the title.
      const link: 'pair' | 'ip' | 'user' =
        ip !== undefined && user !== undefined && samePair >= minFailures
          ? 'pair'
          : sameIp >= minFailures
            ? 'ip'
            : 'user';
      const severity: Severity = link === 'pair' ? 'high' : link === 'ip' ? 'medium' : 'low';
      const confidence: Confidence = link === 'pair' ? 'high' : link === 'ip' ? 'medium' : 'low';
      const first = failEvents.reduce((m, e) => Math.min(m, e.timestamp!), Infinity);
      const account = user ? `"${user}"` : 'unknown account';
      const who = `${account} from ${ip ?? 'unknown IP'}`;
      const title =
        link === 'pair'
          ? `Successful login after ${failures.length} failures: ${who}`
          : link === 'ip'
            ? `Successful login from ${ip} after ${sameIp} failures from that IP`
            : `Login for ${account} after failures from other sources`;
      const finding: Open = {
        key,
        lastSuccess: t,
        severity,
        confidence,
        title,
        reason: `Successful login for ${who} at ${isoUtc(t)} was preceded by ${plural(failures.length, 'failed attempt')} within ${minutes(window)}: ${samePair} from the same IP against the same account, ${sameIp} from the same IP, ${fromUser.length} against the same account.${link === 'user' ? ' None of the failures came from this IP, so the account may simply have been targeted by others while its owner logged in.' : ''} This is a lead to verify, not proof of compromise.`,
        condition: `successful login preceded by ≥ ${minFailures} failures from the same IP or against the same account within ${minutes(window)}`,
        thresholds: [
          { name: 'Prior failures', value: minFailures, unit: 'events' },
          { name: 'Look-back window', value: window, unit: 'minutes' },
        ],
        metric: failures.length,
        primaryThreshold: minFailures,
        eventIds: uniqueIds([...failures, success.id]),
        sourceIps: unique([ip, ...failEvents.map((e) => e.sourceIp)]),
        usernames: unique([user, ...failEvents.map((e) => e.username)]),
        start: first,
        end: t,
        representativeTimestamps: [...new Set([first, t])],
        subjects: { ips: ip ? [ip] : [], users: user ? [user] : [] },
        evidence: [
          {
            label: 'Successful login',
            value: `${isoUtc(t)} (${success.auth?.method ?? 'method unknown'})`,
          },
          { label: 'Failures from same IP and account', value: String(samePair) },
          { label: 'Failures from same IP (any account)', value: String(sameIp) },
          { label: 'Failures against same account (any IP)', value: String(fromUser.length) },
          { label: 'First failure', value: isoUtc(first) },
          {
            label: 'Link between failures and login',
            value:
              link === 'pair'
                ? 'same IP and same account'
                : link === 'ip'
                  ? 'same IP, other accounts'
                  : 'shared account name only',
          },
        ],
        extraLimitations: UNTIMED_NOTE(ctx),
      };
      all.push(finding);
      open.set(key, finding);
    }
    return all.map(({ lastSuccess: _unused, ...f }) => f);
  },
};

export const AUTH_005: RuleDefinition = {
  id: 'AUTH-005',
  name: 'Authentication failures across many accounts',
  category: 'authentication',
  scope: 'global',
  description:
    'Failed logins against many different accounts from several source addresses within a window. Unlike AUTH-003, this looks across all sources, which can reveal distributed guessing.',
  requires: 'Authentication events with an outcome, username, source IP and timestamp.',
  params: [
    countParam(
      'minUsernames',
      'Distinct usernames',
      'Minimum distinct usernames with failures within the window (all sources).',
      10,
      2,
      100_000,
      'accounts',
    ),
    windowParam(30),
    countParam(
      'minSourceIps',
      'Distinct source IPs',
      'Minimum distinct source IPs involved in the episode.',
      2,
      1,
      100_000,
      'IPs',
    ),
  ],
  recommendations: [
    'Review the list of source IPs for shared infrastructure (same network, hosting provider, or user agent).',
    'Check whether any targeted account authenticated successfully afterwards.',
    'Consider global rate limiting or temporary restrictions on password authentication.',
  ],
  limitations: [
    ...COMMON_AUTH_LIMITATIONS,
    'Busy systems with many legitimate users can exceed the threshold; tune it to your normal failure volume.',
  ],
  falsePositives: [
    'A widespread password expiry or SSO outage causing many users to fail at once.',
  ],
  mitre: [{ id: 'T1110', name: 'Brute Force' }],
  applicable: (ctx) =>
    ctx.authFailures.some((e) => e.username)
      ? null
      : 'No timestamped authentication failures with a username.',
  evaluate(ctx, p) {
    const minUsers = p.minUsernames!;
    const window = p.windowMinutes!;
    const minIps = p.minSourceIps!;
    const items = ctx.authFailures
      .filter((e) => e.username)
      .map((e) => ({ t: e.timestamp!, id: e.id, key: e.username! }));
    const findings: Finding[] = [];
    for (const b of findDistinctBursts(items, window * MINUTE, minUsers)) {
      const evs = pick(ctx, b.ids);
      const users = unique(evs.map((e) => e.username));
      const ips = unique(evs.map((e) => e.sourceIp));
      if (ips.length < minIps) continue;
      findings.push({
        key: `global:${b.start}`,
        severity: users.length >= minUsers * 3 ? 'high' : 'medium',
        confidence: ips.length >= 3 ? 'medium' : 'low',
        title: `Failures across ${users.length} accounts from ${ips.length} source IPs`,
        reason: `${plural(b.count, 'failed login')} against ${plural(users.length, 'distinct account')} from ${plural(ips.length, 'source IP')} between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} distinct accounts within ${minutes(window)}; threshold is ${minUsers}.`,
        condition: `distinct usernames with failures (all sources) ≥ ${minUsers} within ${minutes(window)}, involving ≥ ${minIps} source IPs`,
        thresholds: [
          { name: 'Distinct usernames', value: minUsers, unit: 'accounts' },
          { name: 'Window', value: window, unit: 'minutes' },
          { name: 'Distinct source IPs', value: minIps, unit: 'IPs' },
        ],
        metric: b.peak,
        primaryThreshold: minUsers,
        eventIds: b.ids,
        sourceIps: ips,
        usernames: users,
        start: b.start,
        end: b.end,
        representativeTimestamps: representative(b.start, b.peakAt, b.end),
        evidence: [
          { label: 'Accounts', value: `${users.length}: ${listPreview(users, 8)}` },
          { label: 'Top source IPs', value: topList(evs.map((e) => e.sourceIp)) },
        ],
        extraLimitations: UNTIMED_NOTE(ctx),
      });
    }
    return findings;
  },
};

export const AUTH_006: RuleDefinition = {
  id: 'AUTH-006',
  name: 'Unusually high login activity',
  category: 'authentication',
  scope: 'global',
  description:
    'The total number of authentication attempts (successful and failed) within a window exceeds a configured volume.',
  requires: 'Authentication events with an outcome and timestamp.',
  params: [
    countParam(
      'threshold',
      'Attempts',
      'Minimum authentication attempts (any outcome, all sources) within the window.',
      100,
      2,
    ),
    windowParam(5),
  ],
  recommendations: [
    'Compare with normal login volume for the same time of day.',
    'Break the burst down by source IP and account in the event explorer.',
    'If failures dominate, review AUTH-001/AUTH-003 detections for the same period.',
  ],
  limitations: [
    'A fixed threshold does not adapt to the size of your environment; tune it to your normal peak volume.',
    SEVERITY_ESCALATION_NOTE,
  ],
  falsePositives: [
    'Start-of-day login peaks, batch jobs, or monitoring that authenticates frequently.',
  ],
  mitre: [{ id: 'T1110', name: 'Brute Force' }],
  applicable: (ctx) =>
    ctx.authAttempts.length > 0 ? null : 'No timestamped authentication attempts.',
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    return findBursts(refs(ctx.authAttempts), window * MINUTE, threshold).map((b): Finding => {
      const evs = pick(ctx, b.ids);
      const failures = evs.filter((e) => e.auth?.outcome === 'failure').length;
      const failureShare = failures / evs.length;
      return {
        key: `global:${b.start}`,
        severity: failureShare >= 0.5 ? 'medium' : 'low',
        confidence: 'medium',
        title: `High login activity: ${b.count} attempts`,
        reason: `${plural(b.count, 'authentication attempt')} (${failures} failed, ${b.count - failures} succeeded) between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.`,
        condition: `authentication attempts (all outcomes, all sources) ≥ ${threshold} within ${minutes(window)}`,
        thresholds: [
          { name: 'Attempts', value: threshold, unit: 'events' },
          { name: 'Window', value: window, unit: 'minutes' },
        ],
        metric: b.peak,
        primaryThreshold: threshold,
        eventIds: b.ids,
        sourceIps: unique(evs.map((e) => e.sourceIp)),
        usernames: unique(evs.map((e) => e.username)),
        start: b.start,
        end: b.end,
        representativeTimestamps: representative(b.start, b.peakAt, b.end),
        evidence: [
          { label: 'Failure share', value: `${Math.round(failureShare * 100)}%` },
          { label: 'Top source IPs', value: topList(evs.map((e) => e.sourceIp)) },
          { label: 'Top accounts', value: topList(evs.map((e) => e.username)) },
        ],
        extraLimitations: UNTIMED_NOTE(ctx),
      };
    });
  },
};

export const AUTH_007: RuleDefinition = {
  id: 'AUTH-007',
  name: 'Login attempts for non-existent accounts',
  category: 'authentication',
  scope: 'ip',
  description:
    'One source tries many usernames that the service reports as invalid. This is typical of automated scanning with username dictionaries (for example admin, test, oracle).',
  requires:
    'Authentication events flagged as invalid-user (e.g. sshd "Invalid user"), with source IP and timestamp.',
  params: [
    countParam(
      'minUsernames',
      'Distinct invalid usernames',
      'Minimum distinct non-existent usernames tried by one IP within the window.',
      5,
      1,
      10_000,
      'accounts',
    ),
    windowParam(30),
  ],
  recommendations: [
    'Usually low risk on its own, because the accounts do not exist; check whether the same IP also targeted real accounts.',
    'Consider blocking or rate limiting the source if it is not expected.',
  ],
  limitations: [
    'Depends on the service reporting invalid users; many structured logs do not include this flag.',
    'Distinct usernames are counted, so "Invalid user" and "Failed password for invalid user" lines for the same attempt are not double counted.',
  ],
  falsePositives: [
    'Users mistyping their username; misconfigured clients with a wrong default username.',
  ],
  mitre: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1589.003', name: 'Gather Victim Identity Information: Employee Names' },
  ],
  applicable: (ctx) =>
    ctx.events.some((e) => e.auth?.invalidUser && e.timestamp !== undefined && e.sourceIp)
      ? null
      : 'No timestamped invalid-user events with a source IP.',
  evaluate(ctx, p) {
    const minUsers = p.minUsernames!;
    const window = p.windowMinutes!;
    const invalid = ctx.timedEvents.filter(
      (e) => e.category === 'authentication' && e.auth?.invalidUser && e.sourceIp && e.username,
    );
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(invalid, (e) => e.sourceIp)) {
      const items = events.map((e) => ({ t: e.timestamp!, id: e.id, key: e.username! }));
      for (const b of findDistinctBursts(items, window * MINUTE, minUsers)) {
        const users = unique(pick(ctx, b.ids).map((e) => e.username));
        findings.push({
          key: ip,
          severity: users.length >= minUsers * 4 ? 'medium' : 'low',
          confidence: 'high',
          title: `Non-existent usernames tried from ${ip}`,
          reason: `${ip} tried ${plural(users.length, 'username')} that do not exist on the host between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${minUsers}.`,
          condition: `distinct invalid usernames from the same IP ≥ ${minUsers} within ${minutes(window)}`,
          thresholds: [
            { name: 'Distinct invalid usernames', value: minUsers, unit: 'accounts' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: minUsers,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: users,
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [{ label: 'Usernames tried', value: listPreview(users, 10) }],
        });
      }
    }
    return findings;
  },
};

export const AUTH_RULES: RuleDefinition[] = [
  AUTH_001,
  AUTH_002,
  AUTH_003,
  AUTH_004,
  AUTH_005,
  AUTH_006,
  AUTH_007,
];
