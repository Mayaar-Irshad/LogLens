import {
  SEVERITY_RANK,
  type Detection,
  type RuleId,
  type Severity,
} from '../../../types/detection';
import { isoUtc, listPreview, plural, unique, uniqueIds } from '../engine/context';
import type { Finding, RuleDefinition } from '../engine/types';
import { topCounts } from '../engine/windows';
import { countParam } from './params';

const MINUTE = 60_000;
/** Upper bound on baseline buckets; larger spans use proportionally wider buckets. */
export const MAX_BASELINE_BUCKETS = 20_000;

const topList = (values: Array<string | undefined>, n = 5): string =>
  topCounts(values, n)
    .map((c) => `${c.key} (${c.count})`)
    .join(', ') || 'none';

export const GEN_001: RuleDefinition = {
  id: 'GEN-001',
  name: 'Malformed or incomplete log records',
  category: 'general',
  scope: 'dataset',
  description:
    'A notable share of records could not be parsed, or were parsed with missing or invalid critical fields (for example timestamps or addresses). Gaps in log quality limit every other detection.',
  requires: 'Parsing statistics (always available).',
  params: [
    countParam(
      'minPercent',
      'Share of affected records',
      'Minimum percentage of records that are rejected or partial.',
      5,
      1,
      100,
      '%',
    ),
    countParam(
      'minRecords',
      'Affected records',
      'Minimum number of rejected or partial records.',
      10,
      1,
      1_000_000,
      'records',
    ),
  ],
  recommendations: [
    'Confirm the selected format matches the file; a wrong format choice rejects most lines.',
    'Inspect the rejected-record samples on the data source page for truncation or unexpected content.',
    'Check log rotation, shipping and storage for truncation or corruption; unexplained gaps can also follow log tampering.',
  ],
  limitations: [
    'Malformed records are usually caused by format mismatches, multi-format files, or truncated writes, not by attacks.',
  ],
  falsePositives: [
    'Files that mix several log formats',
    'Logs with custom formats or extra fields',
  ],
  mitre: [{ id: 'T1070', name: 'Indicator Removal' }],
  applicable: (ctx) => (ctx.stats ? null : 'Parsing statistics are unavailable.'),
  evaluate(ctx, p) {
    const stats = ctx.stats!;
    const records = stats.parsedRecords + stats.partialRecords + stats.rejectedRecords;
    const affected = stats.partialRecords + stats.rejectedRecords;
    if (records === 0) return [];
    const pct = (affected / records) * 100;
    if (affected < p.minRecords! || pct < p.minPercent!) return [];
    const partial = ctx.events.filter((e) => e.status === 'partial');
    const missingIpAuth = ctx.events.filter(
      (e) => e.category === 'authentication' && e.auth?.outcome && !e.sourceIp,
    ).length;
    return [
      {
        key: 'dataset',
        severity: pct >= 20 ? 'low' : 'info',
        confidence: 'high',
        title: `${Math.round(pct)}% of records were malformed or incomplete`,
        reason: `${plural(affected, 'record')} out of ${records.toLocaleString('en-US')} (${pct.toFixed(1)}%) were rejected (${stats.rejectedRecords}) or partially parsed (${stats.partialRecords}). Thresholds: at least ${p.minRecords} records and ${p.minPercent}%.`,
        condition: `rejected + partial records ≥ ${p.minRecords} and ≥ ${p.minPercent}% of all records`,
        thresholds: [
          { name: 'Affected records', value: p.minRecords!, unit: 'records' },
          { name: 'Share of records', value: p.minPercent!, unit: '%' },
        ],
        metric: affected,
        primaryThreshold: p.minRecords!,
        eventIds: partial.map((e) => e.id),
        sourceIps: [],
        usernames: [],
        representativeTimestamps: [],
        evidence: [
          { label: 'Rejected records', value: String(stats.rejectedRecords) },
          { label: 'Partially parsed records', value: String(stats.partialRecords) },
          {
            label: 'Events without a valid timestamp',
            value: String(stats.eventsWithoutTimestamp),
          },
          { label: 'Authentication attempts without a source IP', value: String(missingIpAuth) },
          {
            label: 'Most common issues',
            value: topList(
              partial.flatMap((e) => e.issues ?? []),
              3,
            ),
          },
        ],
      },
    ];
  },
};

export function median(values: ArrayLike<number>): number {
  if (values.length === 0) return 0;
  const sorted = Array.from(values).sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

/** Choose the bucket size: the configured size, widened if the span would need too many buckets. */
export function baselineBucketMs(spanMs: number, bucketMinutes: number): number {
  const base = bucketMinutes * MINUTE;
  if (spanMs / base + 1 <= MAX_BASELINE_BUCKETS) return base;
  return Math.ceil(spanMs / (MAX_BASELINE_BUCKETS - 1) / MINUTE) * MINUTE;
}

export const GEN_002: RuleDefinition = {
  id: 'GEN-002',
  name: 'Event volume spike compared with baseline',
  category: 'general',
  scope: 'global',
  description:
    'Event volume in a time bucket is far above the typical (median) bucket of the same dataset. The baseline is computed only from the uploaded data.',
  requires: 'Timestamped events spanning at least the configured number of buckets.',
  params: [
    countParam('bucketMinutes', 'Bucket size', 'Size of each time bucket.', 5, 1, 1440, 'min'),
    countParam(
      'multiplier',
      'Multiplier',
      'A bucket is a spike when it has at least this multiple of the median bucket count.',
      3,
      2,
      1000,
      '×',
    ),
    countParam(
      'minBuckets',
      'Minimum buckets',
      'Minimum number of buckets needed before a baseline is computed.',
      12,
      4,
      10_000,
      'buckets',
    ),
    countParam(
      'minEvents',
      'Minimum events',
      'A spike bucket must also contain at least this many events.',
      20,
      1,
      1_000_000,
      'events',
    ),
  ],
  recommendations: [
    'Break the spike down by category, source IP and action to see what drove it.',
    'Compare with deployments, backups, or scheduled jobs at the same time.',
    'Look for related detections in the same time range.',
  ],
  limitations: [
    'The baseline is the median of this dataset only; short or highly irregular logs produce weak baselines.',
    'Spikes are relative: in a quiet log a modest burst can qualify, in a busy log a large attack may not.',
  ],
  falsePositives: ['Scheduled jobs, backups, log rotation catch-up, or daily traffic peaks'],
  mitre: [],
  applicable(ctx, p) {
    const timed = ctx.timedEvents;
    if (timed.length === 0) return 'No timestamped events.';
    const span = timed[timed.length - 1]!.timestamp! - timed[0]!.timestamp!;
    const buckets = Math.floor(span / baselineBucketMs(span, p.bucketMinutes!)) + 1;
    return buckets >= p.minBuckets!
      ? null
      : `Insufficient data for a baseline: ${buckets} bucket(s) of ${p.bucketMinutes} min, ${p.minBuckets} required.`;
  },
  evaluate(ctx, p) {
    const timed = ctx.timedEvents;
    const first = timed[0]!.timestamp!;
    const span = timed[timed.length - 1]!.timestamp! - first;
    const bucketMs = baselineBucketMs(span, p.bucketMinutes!);
    const n = Math.floor(span / bucketMs) + 1;
    const counts = new Int32Array(n);
    for (const e of timed) counts[Math.floor((e.timestamp! - first) / bucketMs)]!++;
    const baseline = median(counts);
    const threshold = Math.max(p.minEvents!, Math.ceil(p.multiplier! * baseline));
    const findings: Finding[] = [];
    let i = 0;
    let cursor = 0;
    while (i < n) {
      if (counts[i]! < threshold) {
        i++;
        continue;
      }
      let j = i;
      let peak = 0;
      let peakIdx = i;
      while (j < n && counts[j]! >= threshold) {
        if (counts[j]! > peak) {
          peak = counts[j]!;
          peakIdx = j;
        }
        j++;
      }
      const start = first + i * bucketMs;
      const end = first + j * bucketMs - 1;
      while (cursor < timed.length && timed[cursor]!.timestamp! < start) cursor++;
      const evs = [];
      let k = cursor;
      while (k < timed.length && timed[k]!.timestamp! <= end) evs.push(timed[k++]!);
      const ratio = peak / Math.max(baseline, 1);
      const bucketLabel = `${Math.round(bucketMs / MINUTE)} min`;
      findings.push({
        key: `spike:${start}`,
        severity: ratio >= 10 ? 'medium' : 'low',
        confidence: n >= 48 ? 'medium' : 'low',
        title: `Event volume spike: ${peak} events in ${bucketLabel}`,
        reason: `Between ${isoUtc(start)} and ${isoUtc(end + 1)}, ${j - i} consecutive ${bucketLabel} bucket(s) reached up to ${peak} events, against a median of ${baseline} per bucket over ${n} buckets. Spike threshold: ${threshold} (max of ${p.multiplier}× median and ${p.minEvents} events).`,
        condition: `bucket count ≥ max(${p.multiplier} × median bucket count, ${p.minEvents}), with ≥ ${p.minBuckets} buckets of data`,
        thresholds: [
          { name: 'Multiplier', value: p.multiplier!, unit: '×' },
          { name: 'Bucket size', value: Math.round(bucketMs / MINUTE), unit: 'minutes' },
          { name: 'Minimum events', value: p.minEvents!, unit: 'events' },
          { name: 'Computed spike threshold', value: threshold, unit: 'events' },
        ],
        metric: peak,
        primaryThreshold: threshold,
        eventIds: evs.map((e) => e.id),
        sourceIps: topCounts(
          evs.map((e) => e.sourceIp),
          10,
        ).map((c) => c.key),
        usernames: topCounts(
          evs.map((e) => e.username),
          10,
        ).map((c) => c.key),
        start,
        end,
        representativeTimestamps: [...new Set([start, first + peakIdx * bucketMs, end])],
        evidence: [
          { label: 'Median events per bucket', value: String(baseline) },
          {
            label: 'Peak bucket',
            value: `${peak} events at ${isoUtc(first + peakIdx * bucketMs)}`,
          },
          { label: 'Categories', value: topList(evs.map((e) => e.category)) },
          { label: 'Top source IPs', value: topList(evs.map((e) => e.sourceIp)) },
        ],
        extraLimitations:
          bucketMs !== p.bucketMinutes! * MINUTE
            ? [
                `The data spans a long period, so buckets were widened to ${bucketLabel} to stay within ${MAX_BASELINE_BUCKETS.toLocaleString('en-US')} buckets.`,
              ]
            : [],
      });
      i = j;
    }
    return findings
      .sort((a, b) => b.metric - a.metric)
      .slice(0, 50)
      .sort((a, b) => (a.start ?? 0) - (b.start ?? 0));
  },
};

const RANKED: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const bump = (s: Severity, cap: Severity): Severity => {
  const next = RANKED[Math.min(SEVERITY_RANK[s] + 1, SEVERITY_RANK[cap])]!;
  return SEVERITY_RANK[next] > SEVERITY_RANK[s] ? next : s;
};
const BRUTE_FORCE_RULES = new Set<RuleId>(['AUTH-001', 'AUTH-002', 'AUTH-003']);

/**
 * Kinds of signal. Several rules can fire on the same underlying activity
 * (a scanner trips the 4xx, probing and scanner-agent rules at once), so the
 * severity bump counts independent kinds, not rules.
 */
export const SIGNAL_FAMILY: Partial<Record<RuleId, string>> = {
  'AUTH-001': 'credential guessing',
  'AUTH-002': 'credential guessing',
  'AUTH-003': 'credential guessing',
  'AUTH-005': 'credential guessing',
  'AUTH-006': 'credential guessing',
  'AUTH-007': 'credential guessing',
  'WEB-007': 'credential guessing',
  'AUTH-004': 'account access',
  'WEB-001': 'reconnaissance',
  'WEB-003': 'reconnaissance',
  'WEB-004': 'reconnaissance',
  'WEB-009': 'reconnaissance',
  'WEB-005': 'exploitation attempts',
  'WEB-008': 'exploitation attempts',
  'WEB-002': 'service errors',
  'WEB-006': 'request volume',
};

const overlaps = (a: Detection, b: Detection): boolean =>
  a.start !== undefined &&
  b.start !== undefined &&
  b.start <= (a.end ?? a.start) &&
  (b.end ?? b.start) >= a.start;

export const GEN_003: RuleDefinition = {
  id: 'GEN-003',
  name: 'Indicator associated with multiple detection rules',
  category: 'general',
  scope: 'dataset',
  description:
    'The same source IP or account is the subject of detections from several independent rules. Converging signals raise investigation priority; they do not establish attribution.',
  requires: 'Detections from other rules.',
  params: [
    countParam(
      'minRules',
      'Distinct rules',
      'Minimum number of different rules that flagged the same IP or account.',
      2,
      2,
      20,
      'rules',
    ),
  ],
  recommendations: [
    'Start the investigation with this indicator: open each related detection and build a timeline.',
    'Pivot to the event explorer filtered by this indicator to see all of its activity.',
    'If a success-after-failure detection is involved, verify the login with the account owner first.',
  ],
  limitations: [
    'Correlation is by exact IP or username match only; related infrastructure (neighbouring IPs, renamed accounts) is not linked.',
    'Several rules can fire on the same underlying activity (for example 4xx bursts and path probing). Severity is therefore raised only when three independent kinds of signal agree, and to critical only when a strongly linked login follows overlapping brute force.',
  ],
  falsePositives: ['Busy shared infrastructure such as proxies or NAT gateways'],
  mitre: [],
  applicable: () => null,
  evaluate: () => [],
  correlate(detections, p) {
    const minRules = p.minRules!;
    const byIndicator = new Map<string, Detection[]>();
    for (const d of detections) {
      if (d.ruleCategory === 'general') continue;
      for (const ip of d.subjects.ips) {
        const k = `ip:${ip}`;
        byIndicator.set(k, [...(byIndicator.get(k) ?? []), d]);
      }
      for (const user of d.subjects.users) {
        const k = `user:${user}`;
        byIndicator.set(k, [...(byIndicator.get(k) ?? []), d]);
      }
    }
    const findings: Finding[] = [];
    for (const [key, related] of [...byIndicator].sort(([a], [b]) => (a < b ? -1 : 1))) {
      const ruleIds = unique(related.map((d) => d.ruleId)).sort();
      if (ruleIds.length < minRules) continue;
      const [kind, ...rest] = key.split(':');
      const value = rest.join(':');
      let severity = related.reduce<Severity>(
        (max, d) => (SEVERITY_RANK[d.severity] > SEVERITY_RANK[max] ? d.severity : max),
        'info',
      );
      const families = unique(ruleIds.map((r) => SIGNAL_FAMILY[r] ?? r));
      if (families.length >= 3) severity = bump(severity, 'high');
      // Critical only when a login is strongly tied to the failures before it (same IP and
      // account) and a brute-force detection on this indicator overlaps that episode in time.
      const possibleCompromise = related.some(
        (a) =>
          a.ruleId === 'AUTH-004' &&
          a.severity === 'high' &&
          related.some((b) => BRUTE_FORCE_RULES.has(b.ruleId) && overlaps(a, b)),
      );
      if (possibleCompromise) severity = 'critical';
      const starts = related.map((d) => d.start).filter((t): t is number => t !== undefined);
      const ends = related.map((d) => d.end).filter((t): t is number => t !== undefined);
      const start = starts.length ? starts.reduce((a, b) => Math.min(a, b)) : undefined;
      const end = ends.length ? ends.reduce((a, b) => Math.max(a, b)) : undefined;
      const label = kind === 'ip' ? 'Source IP' : 'Account';
      findings.push({
        key,
        severity,
        confidence: families.length >= 2 ? 'high' : 'medium',
        title: `${label} ${value} flagged by ${ruleIds.length} rules`,
        reason: `${label} ${value} is the subject of ${plural(related.length, 'detection')} from ${ruleIds.length} rules (${ruleIds.join(', ')})${start !== undefined ? ` between ${isoUtc(start)} and ${isoUtc(end)}` : ''}.${possibleCompromise ? ' This includes a successful login after repeated failures, so a possible account compromise should be ruled out first.' : ''}`,
        condition: `the same IP or account is the subject of detections from ≥ ${minRules} different rules`,
        thresholds: [{ name: 'Distinct rules', value: minRules, unit: 'rules' }],
        metric: ruleIds.length,
        primaryThreshold: minRules,
        eventIds: uniqueIds(related.flatMap((d) => d.eventIds)),
        sourceIps: kind === 'ip' ? [value] : unique(related.flatMap((d) => d.subjects.ips)),
        usernames: kind === 'user' ? [value] : unique(related.flatMap((d) => d.subjects.users)),
        ...(start !== undefined ? { start } : {}),
        ...(end !== undefined ? { end } : {}),
        representativeTimestamps:
          start !== undefined && end !== undefined ? [...new Set([start, end])] : [],
        evidence: [
          {
            label: 'Rules',
            value: related
              .map((d) => `${d.ruleId} ${d.ruleName}`)
              .filter((v, i, a) => a.indexOf(v) === i)
              .join('; '),
          },
          { label: 'Related detections', value: String(related.length) },
          {
            label: 'Independent kinds of signal',
            value: `${families.length}: ${families.join(', ')}`,
          },
          {
            label: 'Highest contributing severity',
            value: related
              .map((d) => d.severity)
              .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0]!,
          },
          {
            label: 'Other indicators involved',
            value: listPreview(
              unique(related.flatMap((d) => (kind === 'ip' ? d.subjects.users : d.subjects.ips))),
              6,
            ),
          },
        ],
        relatedDetectionIds: related.map((d) => d.id),
        subjects: kind === 'ip' ? { ips: [value], users: [] } : { ips: [], users: [value] },
      });
    }
    return findings;
  },
};

export const GENERAL_RULES: RuleDefinition[] = [GEN_001, GEN_002, GEN_003];
