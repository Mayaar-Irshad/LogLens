import type {
  CountItem,
  DashboardMetrics,
  DisplayTimeZone,
  TimeBucket,
} from '../../types/analytics';
import { SEVERITIES } from '../../types/detection';
import type { NormalizedEvent } from '../../types/events';
import type { DetectionIndex } from './detectionIndex';
import { hourOf, statusClassOf } from './filterEvents';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const NICE_BUCKETS = [
  MINUTE,
  2 * MINUTE,
  5 * MINUTE,
  10 * MINUTE,
  15 * MINUTE,
  30 * MINUTE,
  HOUR,
  2 * HOUR,
  3 * HOUR,
  6 * HOUR,
  12 * HOUR,
  DAY,
  2 * DAY,
  7 * DAY,
  30 * DAY,
];

export const TARGET_BUCKETS = 96;
export const TOP_N = 10;

/** Smallest "nice" bucket that keeps the timeline within the target bucket count. */
export function chooseBucketMs(spanMs: number, target = TARGET_BUCKETS): number {
  for (const b of NICE_BUCKETS) if (spanMs / b <= target) return b;
  return Math.ceil(spanMs / target / DAY) * DAY;
}

/** Bucket start aligned to the display zone (so "1 day" means a local day for 'local'). */
export function bucketStart(ms: number, bucketMs: number, tz: DisplayTimeZone): number {
  const offset = tz === 'UTC' ? 0 : -new Date(ms).getTimezoneOffset() * MINUTE;
  return Math.floor((ms + offset) / bucketMs) * bucketMs - offset;
}

class Counter {
  private readonly map = new Map<string, number>();
  add(key: string | undefined, n = 1): void {
    if (key === undefined) return;
    this.map.set(key, (this.map.get(key) ?? 0) + n);
  }
  get size(): number {
    return this.map.size;
  }
  get(key: string): number {
    return this.map.get(key) ?? 0;
  }
  top(n: number): CountItem[] {
    const items: CountItem[] = [];
    for (const [key, count] of this.map) items.push({ key, count });
    items.sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    return n === Infinity ? items : items.slice(0, n);
  }
}

const emptyBucket = (t: number): TimeBucket => ({
  t,
  total: 0,
  authSuccess: 0,
  authFailure: 0,
  web2xx: 0,
  web3xx: 0,
  web4xx: 0,
  web5xx: 0,
  other: 0,
});

/**
 * Compute every dashboard aggregate for a set of events in two passes. All
 * charts and counters derive from this one function, so a filter changes them
 * consistently.
 */
export function computeMetrics(
  events: readonly NormalizedEvent[],
  ids: Iterable<number> | null,
  options: { timeZone: DisplayTimeZone; index?: DetectionIndex },
): DashboardMetrics {
  const tz = options.timeZone;
  // Never spread large arrays into call arguments: engines cap argument counts (~65k–500k).
  const selected: readonly NormalizedEvent[] =
    ids === null ? events : Array.from(ids, (id) => events[id]!);

  const ips = new Counter();
  const users = new Counter();
  const categories = new Counter();
  const formats = new Counter();
  const failedUsers = new Counter();
  const failedIps = new Counter();
  const successUsers = new Counter();
  const statusCodes = new Counter();
  const statusClasses = new Counter();
  const methods = new Counter();
  const paths = new Counter();
  const errorPaths = new Counter();
  const clients = new Counter();
  const agents = new Counter();
  const severities = new Counter();
  const hourly = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    total: 0,
    authFailure: 0,
    authSuccess: 0,
    web: 0,
  }));

  let min = Infinity;
  let max = -Infinity;
  let timed = 0;
  let authTotal = 0;
  let authSuccess = 0;
  let authFailure = 0;
  let invalidUserAttempts = 0;
  let webTotal = 0;
  let bytes = 0;
  let partial = 0;
  let flagged = 0;

  for (const e of selected) {
    ips.add(e.sourceIp);
    users.add(e.username);
    categories.add(e.category);
    formats.add(e.format);
    if (e.status === 'partial') partial++;
    const sev = options.index?.maxSeverity(e.id);
    if (sev) {
      flagged++;
      severities.add(sev);
    }
    const outcome = e.category === 'authentication' ? e.auth?.outcome : undefined;
    if (outcome) {
      authTotal++;
      if (outcome === 'success') {
        authSuccess++;
        successUsers.add(e.username);
      } else {
        authFailure++;
        failedUsers.add(e.username);
        failedIps.add(e.sourceIp);
        if (e.auth?.invalidUser) invalidUserAttempts++;
      }
    }
    if (e.http) {
      webTotal++;
      const st = e.http.status;
      if (st !== undefined) statusCodes.add(String(st));
      statusClasses.add(statusClassOf(st));
      methods.add(e.http.method);
      paths.add(e.http.path);
      if (st !== undefined && st >= 400) errorPaths.add(e.http.path);
      clients.add(e.sourceIp);
      agents.add(e.http.userAgent);
      if (e.http.bytes !== undefined && Number.isFinite(e.http.bytes)) bytes += e.http.bytes;
    }
    if (e.timestamp !== undefined) {
      timed++;
      if (e.timestamp < min) min = e.timestamp;
      if (e.timestamp > max) max = e.timestamp;
      const h = hourly[hourOf(e.timestamp, tz)]!;
      h.total++;
      if (outcome === 'failure') h.authFailure++;
      if (outcome === 'success') h.authSuccess++;
      if (e.http) h.web++;
    }
  }

  let bucketMs = MINUTE;
  const buckets: TimeBucket[] = [];
  if (timed > 0) {
    bucketMs = chooseBucketMs(max - min);
    const map = new Map<number, TimeBucket>();
    for (const e of selected) {
      if (e.timestamp === undefined) continue;
      const key = bucketStart(e.timestamp, bucketMs, tz);
      let b = map.get(key);
      if (!b) {
        b = emptyBucket(key);
        map.set(key, b);
      }
      b.total++;
      const outcome = e.category === 'authentication' ? e.auth?.outcome : undefined;
      if (outcome === 'success') b.authSuccess++;
      else if (outcome === 'failure') b.authFailure++;
      else if (e.http) {
        const c = statusClassOf(e.http.status);
        if (c === '2xx' || c === '1xx') b.web2xx++;
        else if (c === '3xx') b.web3xx++;
        else if (c === '4xx') b.web4xx++;
        else if (c === '5xx') b.web5xx++;
        else b.other++;
      } else b.other++;
    }
    // Fill gaps so quiet periods appear as zero rather than being skipped. In the
    // local zone a DST change can make a "day" 23 or 25 hours long, so the next
    // bucket is recomputed from the zone rather than assumed to be bucketMs later.
    const seen = new Set<number>();
    const last = bucketStart(max, bucketMs, tz);
    let t = bucketStart(min, bucketMs, tz);
    while (t <= last && buckets.length < TARGET_BUCKETS * 4) {
      buckets.push(map.get(t) ?? emptyBucket(t));
      seen.add(t);
      let next = bucketStart(t + bucketMs, bucketMs, tz);
      if (next <= t) next = bucketStart(t + bucketMs + 2 * HOUR, bucketMs, tz);
      t = next;
    }
    for (const [key, b] of map) if (!seen.has(key)) buckets.push(b);
    buckets.sort((a, b) => a.t - b.t);
  }

  return {
    totalEvents: selected.length,
    timedEvents: timed,
    timeRange: timed > 0 ? { start: min, end: max } : {},
    uniqueIps: ips.size,
    uniqueUsers: users.size,
    categories: categories.top(Infinity),
    formats: formats.top(Infinity),
    auth: {
      total: authTotal,
      success: authSuccess,
      failure: authFailure,
      invalidUserAttempts,
      topFailedUsers: failedUsers.top(TOP_N),
      topFailedIps: failedIps.top(TOP_N),
      topSuccessUsers: successUsers.top(TOP_N),
    },
    web: {
      total: webTotal,
      statusCodes: statusCodes.top(Infinity).sort((a, b) => Number(a.key) - Number(b.key)),
      statusClasses: statusClasses.top(Infinity).sort((a, b) => (a.key < b.key ? -1 : 1)),
      methods: methods.top(TOP_N),
      topPaths: paths.top(TOP_N),
      topErrorPaths: errorPaths.top(TOP_N),
      topClients: clients.top(TOP_N),
      topUserAgents: agents.top(TOP_N),
      uniqueClients: clients.size,
      uniquePaths: paths.size,
      bytes,
    },
    topIps: ips.top(TOP_N),
    topUsers: users.top(TOP_N),
    hourly,
    timeline: { bucketMs, buckets },
    partialEvents: partial,
    flaggedEvents: flagged,
    severityByEvent: SEVERITIES.map((s) => ({ key: s, count: severities.get(s) })),
  };
}
