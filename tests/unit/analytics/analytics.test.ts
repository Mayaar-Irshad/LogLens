import { describe, expect, it } from 'vitest';
import {
  bucketStart,
  chooseBucketMs,
  computeMetrics,
} from '../../../src/features/analytics/aggregate';
import { DetectionIndex } from '../../../src/features/analytics/detectionIndex';
import {
  compileFilter,
  detectionsInScope,
  filterEventIds,
  hasEventConstraints,
  statusClassOf,
} from '../../../src/features/analytics/filterEvents';
import { computeLanes } from '../../../src/features/analytics/lanes';
import { pageOf, relatedEvents, sortEventIds } from '../../../src/features/analytics/query';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { runDetections } from '../../../src/features/detection/engine/runDetections';
import { build, fail, MIN, ok, req, SEC, T0, times } from '../../helpers/events';

const ATTACKER = '203.0.113.50';
const events = build([
  ...times(10, T0, 10 * SEC).map((t) => fail(t, ATTACKER, 'root')),
  ok(T0 + 5 * MIN, '192.0.2.10', 'alice'),
  req(T0 + 2 * 3600_000, '198.51.100.7', '/index.html', 200, { bytes: 100 }),
  req(T0 + 2 * 3600_000 + SEC, '198.51.100.7', '/missing', 404, { bytes: 20 }),
  req(T0 + 2 * 3600_000 + 2 * SEC, '198.51.100.8', '/api', 503),
  { category: 'system', action: 'syslog_message' },
]);
const run = runDetections(events, defaultDetectionConfig());
const index = new DetectionIndex(run.detections);

describe('compileFilter', () => {
  const ids = (filter: Parameters<typeof filterEventIds>[1]) =>
    filterEventIds(events, filter, index);

  it('returns every event for an empty filter', () => {
    expect(ids({})).toHaveLength(events.length);
    expect(hasEventConstraints({ timeZone: 'UTC' })).toBe(false);
    expect(hasEventConstraints({ timeRange: {} })).toBe(false);
    expect(hasEventConstraints({ sourceIps: ['x'] })).toBe(true);
  });

  it('filters by IP, user, category and outcome (AND across, OR within)', () => {
    expect(ids({ sourceIps: [ATTACKER] })).toHaveLength(10);
    expect(ids({ sourceIps: [ATTACKER, '192.0.2.10'] })).toHaveLength(11);
    expect(ids({ sourceIps: [ATTACKER], usernames: ['alice'] })).toEqual([]);
    expect(ids({ categories: ['web'] })).toEqual([11, 12, 13]);
    expect(ids({ authOutcomes: ['success'] })).toEqual([10]);
  });

  it('excludes events without timestamps when a time range is active', () => {
    expect(ids({ timeRange: { start: T0 } })).not.toContain(14);
    expect(ids({ timeRange: { start: T0 + 3600_000 } })).toEqual([11, 12, 13]);
    expect(ids({ timeRange: { start: T0, end: T0 + 10 * SEC } })).toEqual([0, 1]);
  });

  it('filters by HTTP status, class, method, path and hour', () => {
    expect(ids({ httpStatuses: [404] })).toEqual([12]);
    expect(ids({ statusClasses: ['5xx'] })).toEqual([13]);
    expect(ids({ httpMethods: ['GET'] })).toHaveLength(3);
    expect(ids({ paths: ['/api'] })).toEqual([13]);
    expect(ids({ hours: [12], timeZone: 'UTC' })).toEqual([11, 12, 13]);
  });

  it('filters events that support selected detections', () => {
    const bruteForce = run.detections.find((d) => d.ruleId === 'AUTH-001')!;
    expect(ids({ detectionIds: [bruteForce.id] })).toEqual(bruteForce.eventIds);
    expect(ids({ detectionIds: [] })).toEqual([]);
    expect(ids({ detectionIds: ['unknown'] })).toEqual([]);
  });

  it('searches the original line case-insensitively and treats regex characters literally', () => {
    expect(ids({ search: 'SYNTHETIC EVENT 3' })).toEqual([3]);
    expect(ids({ search: '.*' })).toEqual([]);
  });

  it('filters by parse status and format', () => {
    expect(ids({ parseStatuses: ['partial'] })).toEqual([]);
    expect(ids({ formats: ['apache'] })).toEqual([11, 12, 13]);
  });

  it('derives detections in scope from the filtered events', () => {
    const matching = ids({ sourceIps: ['198.51.100.7'] });
    expect(detectionsInScope(matching, { sourceIps: ['198.51.100.7'] }, index)).toEqual([]);
    const attackerIds = ids({ sourceIps: [ATTACKER] });
    expect(detectionsInScope(attackerIds, { sourceIps: [ATTACKER] }, index)).toEqual(
      expect.arrayContaining([run.detections.find((d) => d.ruleId === 'AUTH-001')!.id]),
    );
    expect(detectionsInScope(attackerIds, {}, index)).toBeNull();
  });

  it('compiles reusable predicates', () => {
    const p = compileFilter({ usernames: ['root'] });
    expect(p(events[0]!)).toBe(true);
    expect(p(events[10]!)).toBe(false);
    expect(statusClassOf(undefined)).toBeUndefined();
    expect(statusClassOf(999)).toBeUndefined();
  });
});

describe('computeMetrics', () => {
  const m = computeMetrics(events, null, { timeZone: 'UTC', index });

  it('computes counters from the actual events', () => {
    expect(m).toMatchObject({
      totalEvents: 15,
      timedEvents: 14,
      uniqueIps: 4,
      uniqueUsers: 2,
      partialEvents: 0,
    });
    expect(m.auth).toMatchObject({ total: 11, success: 1, failure: 10 });
    expect(m.auth.topFailedIps).toEqual([{ key: ATTACKER, count: 10 }]);
    expect(m.web).toMatchObject({ total: 3, bytes: 120 });
    expect(m.web.statusCodes).toEqual([
      { key: '200', count: 1 },
      { key: '404', count: 1 },
      { key: '503', count: 1 },
    ]);
    expect(m.timeRange).toEqual({ start: T0, end: T0 + 2 * 3600_000 + 2 * SEC });
  });

  it('builds an hourly histogram and a gap-filled timeline', () => {
    expect(m.hourly[10]).toMatchObject({ total: 11, authFailure: 10, authSuccess: 1 });
    expect(m.hourly[12]).toMatchObject({ total: 3, web: 3 });
    const total = m.timeline.buckets.reduce((s, b) => s + b.total, 0);
    expect(total).toBe(14);
    const steps = m.timeline.buckets.slice(1).map((b, i) => b.t - m.timeline.buckets[i]!.t);
    expect(new Set(steps)).toEqual(new Set([m.timeline.bucketMs]));
    const web = m.timeline.buckets.reduce((s, b) => s + b.web2xx + b.web4xx + b.web5xx, 0);
    expect(web).toBe(3);
  });

  it('counts events behind detections by highest severity', () => {
    expect(m.flaggedEvents).toBeGreaterThanOrEqual(10);
    expect(m.severityByEvent.map((s) => s.key)).toEqual([
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ]);
  });

  it('aggregates only the selected ids', () => {
    const sub = computeMetrics(events, [11, 12], { timeZone: 'UTC' });
    expect(sub).toMatchObject({ totalEvents: 2, uniqueIps: 1, flaggedEvents: 0 });
    expect(sub.auth.total).toBe(0);
  });

  it('handles an empty selection', () => {
    const empty = computeMetrics(events, [], { timeZone: 'UTC' });
    expect(empty).toMatchObject({ totalEvents: 0, timedEvents: 0, timeRange: {} });
    expect(empty.timeline.buckets).toEqual([]);
  });

  it('chooses nice bucket sizes and aligns them', () => {
    expect(chooseBucketMs(30 * MIN)).toBe(MIN);
    expect(chooseBucketMs(24 * 3600_000)).toBe(15 * MIN);
    expect(chooseBucketMs(365 * 24 * 3600_000)).toBe(7 * 24 * 3600_000);
    expect(chooseBucketMs(10 * 365 * 24 * 3600_000)).toBeGreaterThanOrEqual(30 * 24 * 3600_000);
    expect(bucketStart(T0 + 7 * MIN, 5 * MIN, 'UTC')).toBe(T0 + 5 * MIN);
  });
});

describe('sorting, paging and related events', () => {
  it('sorts without mutating and keeps missing values last in both directions', () => {
    const ids = events.map((e) => e.id);
    const asc = sortEventIds(events, ids, { field: 'timestamp', direction: 'asc' });
    const desc = sortEventIds(events, ids, { field: 'timestamp', direction: 'desc' });
    expect(asc[asc.length - 1]).toBe(14);
    expect(desc[desc.length - 1]).toBe(14);
    expect(desc[0]).toBe(13);
    expect(ids).toEqual(events.map((e) => e.id));
    const byUser = sortEventIds(events, ids, { field: 'username', direction: 'asc' });
    expect(events[byUser[0]!]!.username).toBe('alice');
    const byStatus = sortEventIds(events, ids, { field: 'status', direction: 'desc' });
    expect(events[byStatus[0]!]!.http?.status).toBe(503);
  });

  it('pages with bounds and clamps out-of-range pages', () => {
    const page = pageOf(
      events,
      events.map((e) => e.id),
      99,
      4,
      index,
    );
    expect(page).toMatchObject({ page: 3, pageSize: 4, total: 15 });
    expect(page.rows.map((r) => r.id)).toEqual([12, 13, 14]);
    expect(pageOf(events, [0], 0, 10_000).pageSize).toBe(200);
    const first = pageOf(events, [0], 0, 10, index).rows[0]!;
    expect(first.detectionIds.length).toBeGreaterThan(0);
    expect(first.maxSeverity).toBeDefined();
  });

  it('finds related events by IP, user and time window', () => {
    expect(relatedEvents(events, 0, 'ip', 5, 50).page.total).toBe(9);
    expect(relatedEvents(events, 0, 'user', 5, 50).description).toBe('same username root');
    const win = relatedEvents(events, 10, 'window', 2, 50);
    expect(win.page.rows.every((r) => Math.abs(r.timestamp! - (T0 + 5 * MIN)) <= 2 * MIN)).toBe(
      true,
    );
    expect(relatedEvents(events, 14, 'ip', 5, 50).description).toBe('This event has no source IP.');
    expect(relatedEvents(events, 14, 'user', 5, 50).page.total).toBe(0);
    expect(relatedEvents(events, 14, 'window', 5, 50).description).toBe(
      'This event has no timestamp.',
    );
    expect(relatedEvents(events, 999, 'ip', 5, 50).description).toBe('Event not found.');
  });
});

describe('scale', () => {
  it('aggregates hundreds of thousands of events without exceeding call-argument limits', () => {
    const many = build(
      Array.from({ length: 300_000 }, (_, i) =>
        req(T0 + i * 100, `198.51.100.${i % 200}`, `/p${i % 50}`, 200),
      ),
    );
    const m = computeMetrics(many, null, { timeZone: 'UTC' });
    expect(m.totalEvents).toBe(300_000);
    expect(m.uniqueIps).toBe(200);
    expect(m.timeline.buckets.reduce((s, b) => s + b.total, 0)).toBe(300_000);
  });
});

describe('indicator lanes', () => {
  it('counts events and risky events per indicator on one shared axis', () => {
    const lanes = computeLanes(
      events,
      null,
      [
        { kind: 'ip', value: ATTACKER },
        { kind: 'user', value: 'alice' },
        { kind: 'ip', value: '198.51.100.7' },
      ],
      10,
    );
    expect(lanes.start).toBe(T0);
    expect(lanes.end).toBe(T0 + 2 * 3600_000 + 2 * SEC);
    const [attacker, alice, web] = lanes.lanes;
    expect(attacker).toMatchObject({ total: 10, risky: 10, first: T0, last: T0 + 90 * SEC });
    expect(attacker!.cells[0]).toEqual({ total: 10, risky: 10 });
    expect(alice).toMatchObject({ total: 1, risky: 0 });
    expect(web).toMatchObject({ total: 2, risky: 1 });
    expect(web!.cells[9]!.total).toBe(2);
    expect(lanes.lanes.reduce((s, l) => s + l.cells.reduce((x, c) => x + c.total, 0), 0)).toBe(13);
  });

  it('handles no timed events and caps lanes and cells', () => {
    expect(computeLanes(events, [14], [{ kind: 'ip', value: ATTACKER }], 10)).toMatchObject({
      bucketMs: 0,
    });
    const many = Array.from({ length: 20 }, (_, i) => ({ kind: 'ip' as const, value: `x${i}` }));
    const r = computeLanes(events, null, many, 10_000);
    expect(r.lanes).toHaveLength(12);
    expect(r.lanes[0]!.cells).toHaveLength(240);
  });
});
