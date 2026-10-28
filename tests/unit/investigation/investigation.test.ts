import { describe, expect, it } from 'vitest';
import { initialState, reducer } from '../../../src/app/state';
import {
  buildAlertTimeline,
  byPriority,
  severityCounts,
} from '../../../src/features/investigation/detections';
import {
  clearFilters,
  filterChips,
  filterDetections,
  hasActiveFilters,
  removeChip,
  statusOf,
  toEventFilter,
  toggleFilterValue,
} from '../../../src/features/investigation/filters';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { runDetections } from '../../../src/features/detection/engine/runDetections';
import { summarizeDetection } from '../../../src/workers/analysisService';
import type { AnalysisSummary, RedetectResult } from '../../../src/workers/protocol';
import { build, fail, MIN, ok, SEC, T0, times } from '../../helpers/events';

const detections = runDetections(
  build([
    ...times(12, T0, 10 * SEC).map((t) => fail(t, '203.0.113.50', 'root')),
    ok(T0 + 3 * MIN, '203.0.113.50', 'root'),
  ]),
  defaultDetectionConfig(),
).detections.map(summarizeDetection);

describe('filter translation', () => {
  it('maps dashboard filters to a worker event filter', () => {
    const f = {
      ...clearFilters(),
      sourceIps: ['203.0.113.50'],
      httpStatuses: [404],
      search: '  root ',
      timeRange: { start: T0 },
    };
    expect(toEventFilter(f, detections, {}, 'UTC')).toEqual({
      timeZone: 'UTC',
      timeRange: { start: T0 },
      sourceIps: ['203.0.113.50'],
      httpStatuses: [404],
      search: 'root',
    });
    expect(toEventFilter(clearFilters(), detections, {}, 'local')).toEqual({ timeZone: 'local' });
  });

  it('turns alert-attribute filters into a detection-id constraint', () => {
    const high = detections.filter((d) => d.severity === 'high').map((d) => d.id);
    expect(
      toEventFilter({ ...clearFilters(), severities: ['high'] }, detections, {}, 'UTC')
        .detectionIds,
    ).toEqual(high);
    const reviewedId = detections[0]!.id;
    const ef = toEventFilter(
      { ...clearFilters(), alertStatuses: ['reviewed'] },
      detections,
      { [reviewedId]: 'reviewed' },
      'UTC',
    );
    expect(ef.detectionIds).toEqual([reviewedId]);
    expect(
      toEventFilter({ ...clearFilters(), ruleIds: ['WEB-001'] }, detections, {}, 'UTC')
        .detectionIds,
    ).toEqual([]);
  });

  it('filters detections by attributes and by events in scope', () => {
    expect(filterDetections(detections, clearFilters(), {}, null)).toHaveLength(detections.length);
    expect(
      filterDetections(detections, { ...clearFilters(), ruleIds: ['AUTH-004'] }, {}, null).map(
        (d) => d.ruleId,
      ),
    ).toEqual(['AUTH-004']);
    // Scope only applies when an event filter is active.
    expect(filterDetections(detections, clearFilters(), {}, [])).toHaveLength(detections.length);
    expect(
      filterDetections(detections, { ...clearFilters(), sourceIps: ['192.0.2.1'] }, {}, []),
    ).toEqual([]);
  });

  it('defaults alert status to open and ignores prototype keys', () => {
    expect(statusOf({}, 'x')).toBe('open');
    expect(statusOf({}, '__proto__')).toBe('open');
    expect(statusOf({ a: 'reviewed' }, 'a')).toBe('reviewed');
  });

  it('toggles values, builds chips and removes them', () => {
    let f = toggleFilterValue(clearFilters(), 'sourceIps', '192.0.2.1');
    f = toggleFilterValue(f, 'hours', 3);
    f = { ...f, search: 'sshd' };
    expect(hasActiveFilters(f)).toBe(true);
    const chips = filterChips(f);
    expect(chips.map((c) => c.label)).toEqual(['IP: 192.0.2.1', 'Hour: 03:00 UTC', 'Search: sshd']);
    f = removeChip(f, chips[0]!);
    f = removeChip(f, chips[2]!);
    expect(f.sourceIps).toEqual([]);
    expect(f.search).toBe('');
    expect(toggleFilterValue(f, 'hours', 3).hours).toEqual([]);
    expect(
      removeChip({ ...f, timeRange: { start: 1 } }, { key: 'timeRange', value: 1, label: '' })
        .timeRange,
    ).toEqual({});
    expect(hasActiveFilters(clearFilters())).toBe(false);
  });
});

describe('detection helpers', () => {
  it('orders by severity, then risk, then recency', () => {
    const sorted = [...detections].sort(byPriority);
    expect(sorted[0]!.severity).toBe('critical');
    // Both the IP and the account "root" get a critical correlation (brute force + later success).
    expect(severityCounts(detections)).toMatchObject({ critical: 2 });
  });

  it('buckets detections by start time and severity', () => {
    const { points } = buildAlertTimeline(detections, 'UTC');
    const total = points.reduce((s, p) => s + p.critical + p.high + p.medium + p.low + p.info, 0);
    expect(total).toBe(detections.length);
    expect(buildAlertTimeline([], 'UTC')).toEqual({ points: [], bucketMs: 60_000 });
  });
});

describe('app reducer', () => {
  const summary = {
    source: { name: 'x.log', kind: 'text', sizeBytes: 1 },
    detections,
    ruleRuns: [],
    entities: [],
    posture: { level: 'high', counts: {}, summary: '' },
    metrics: {},
  } as unknown as AnalysisSummary;

  it('moves through the scan lifecycle and clears investigation state on new data', () => {
    let s = reducer(initialState(), { type: 'scanStarted', sourceName: 'x.log' });
    expect(s.scan.phase).toBe('scanning');
    s = reducer(s, {
      type: 'scanProgress',
      progress: {
        phase: 'reading',
        bytesProcessed: 1,
        totalBytes: 2,
        linesProcessed: 1,
        eventsCreated: 1,
      },
    });
    expect(s.scan.progress?.bytesProcessed).toBe(1);
    s = reducer(s, { type: 'scanSucceeded', summary, timeZone: 'UTC' });
    expect(s).toMatchObject({ view: 'overview', scan: { phase: 'ready' } });
    s = reducer(s, { type: 'setStatus', id: detections[0]!.id, status: 'reviewed' });
    s = reducer(s, { type: 'setNote', id: detections[0]!.id, note: 'x'.repeat(20_000) });
    expect(s.notes[detections[0]!.id]).toHaveLength(10_000);
    s = reducer(s, { type: 'setFilters', filters: { ...clearFilters(), usernames: ['root'] } });
    s = reducer(s, { type: 'scanStarted', sourceName: 'y.log' });
    expect(s).toMatchObject({
      statuses: {},
      notes: {},
      caseNote: '',
      summary: null,
      filters: clearFilters(),
    });
  });

  it('keeps review state for detections that survive a re-run', () => {
    let s = reducer(initialState(), { type: 'scanSucceeded', summary, timeZone: 'UTC' });
    s = reducer(s, { type: 'setStatus', id: detections[0]!.id, status: 'reviewed' });
    s = reducer(s, { type: 'setStatus', id: detections[1]!.id, status: 'unresolved' });
    const result = {
      detections: [detections[0]!],
      ruleRuns: [],
      entities: [],
      posture: summary.posture,
      metrics: summary.metrics,
      durationMs: 1,
    } as RedetectResult;
    const version = s.detectionsVersion;
    s = reducer(s, {
      type: 'redetectSucceeded',
      result,
      config: defaultDetectionConfig(),
      timeZone: 'local',
    });
    expect(s.statuses).toEqual({ [detections[0]!.id]: 'reviewed' });
    // Every query is keyed on the version, so a re-run with the same count still refreshes.
    expect(s.detectionsVersion).toBe(version + 1);
    expect(s.baseMetricsTimeZone).toBe('local');
    expect(s.lastRedetect).toEqual({
      before: detections.length,
      after: 1,
      added: 0,
      removed: detections.length - 1,
    });
    s = reducer(s, { type: 'redetectFailed', error: 'boom' });
    expect(s).toMatchObject({ redetecting: false, redetectError: 'boom' });
    // Views that need data fall back to the data source when nothing is loaded.
    expect(reducer(initialState(), { type: 'navigate', view: 'alerts' }).view).toBe('data');
    expect(reducer(initialState(), { type: 'navigate', view: 'rules' }).view).toBe('rules');
  });

  it('handles cancellation, errors and lost datasets', () => {
    let s = reducer(initialState(), { type: 'scanStarted', sourceName: 'x' });
    s = reducer(s, { type: 'scanCancelled' });
    expect(s.scan).toEqual({ phase: 'idle', notice: 'The scan was cancelled. No data was kept.' });
    s = reducer(s, { type: 'scanFailed', error: 'boom' });
    expect(s.scan).toEqual({ phase: 'error', error: 'boom' });
    s = reducer(reducer(s, { type: 'scanSucceeded', summary, timeZone: 'UTC' }), {
      type: 'datasetLost',
      error: 'crashed',
    });
    expect(s).toMatchObject({ summary: null, scan: { phase: 'error', error: 'crashed' } });
    // Progress after the scan finished is ignored.
    expect(
      reducer(s, {
        type: 'scanProgress',
        progress: {
          phase: 'done',
          bytesProcessed: 1,
          totalBytes: 1,
          linesProcessed: 1,
          eventsCreated: 1,
        },
      }),
    ).toBe(s);
  });
});
