import { bucketStart, chooseBucketMs } from '../analytics/aggregate';
import type { DisplayTimeZone } from '../../types/analytics';
import { SEVERITY_RANK, type DetectionSummary, type Severity } from '../../types/detection';

/** Highest severity first, then risk score, then most recent. */
export const byPriority = (a: DetectionSummary, b: DetectionSummary): number =>
  SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
  b.riskScore - a.riskScore ||
  (b.start ?? 0) - (a.start ?? 0);

export function severityCounts(detections: readonly DetectionSummary[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const d of detections) counts[d.severity]++;
  return counts;
}

export interface AlertPoint {
  t: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

const emptyPoint = (t: number): AlertPoint => ({
  t,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

/** Detections bucketed by start time and severity for the alert timeline. Untimed detections are omitted. */
export function buildAlertTimeline(
  detections: readonly DetectionSummary[],
  timeZone: DisplayTimeZone,
): { points: AlertPoint[]; bucketMs: number } {
  const timed = detections.filter((d) => d.start !== undefined);
  if (timed.length === 0) return { points: [], bucketMs: 60_000 };
  const starts = timed.map((d) => d.start!);
  const min = starts.reduce((a, b) => Math.min(a, b));
  const max = starts.reduce((a, b) => Math.max(a, b));
  const bucketMs = chooseBucketMs(max - min, 48);
  const map = new Map<number, AlertPoint>();
  for (let t = bucketStart(min, bucketMs, timeZone); t <= max; t += bucketMs)
    map.set(t, emptyPoint(t));
  for (const d of timed) {
    const key = bucketStart(d.start!, bucketMs, timeZone);
    const p = map.get(key) ?? emptyPoint(key);
    p[d.severity]++;
    map.set(key, p);
  }
  return { points: [...map.values()].sort((a, b) => a.t - b.t), bucketMs };
}
