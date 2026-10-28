import type { NormalizedEvent } from '../../../types/events';
import type { ParseStats } from '../../../types/ingestion';
import type { DetectionContext } from './types';

const byTime = (a: NormalizedEvent, b: NormalizedEvent): number =>
  (a.timestamp ?? 0) - (b.timestamp ?? 0) || a.id - b.id;

/**
 * Pre-compute the event subsets that rules share. Only authentication-category
 * events with an explicit outcome count as attempts (see the parser notes on
 * double counting); privilege events such as sudo are kept separate.
 */
export function buildDetectionContext(
  events: readonly NormalizedEvent[],
  stats?: ParseStats,
): DetectionContext {
  const authAttempts: NormalizedEvent[] = [];
  const webRequests: NormalizedEvent[] = [];
  const timedEvents: NormalizedEvent[] = [];
  const untimed = { auth: 0, web: 0, all: 0 };
  for (const e of events) {
    const timed = e.timestamp !== undefined;
    if (timed) timedEvents.push(e);
    else untimed.all++;
    if (e.category === 'authentication' && e.auth?.outcome) {
      if (timed) authAttempts.push(e);
      else untimed.auth++;
    }
    if (e.http) {
      webRequests.push(e);
      if (!timed) untimed.web++;
    }
  }
  authAttempts.sort(byTime);
  timedEvents.sort(byTime);
  const timedWebRequests = webRequests.filter((e) => e.timestamp !== undefined).sort(byTime);
  return {
    events,
    authAttempts,
    authFailures: authAttempts.filter((e) => e.auth?.outcome === 'failure'),
    webRequests,
    timedWebRequests,
    timedEvents,
    untimed,
    ...(stats ? { stats } : {}),
  };
}

/** Timestamp text used inside detection explanations (always UTC, zone explicit). */
export function isoUtc(ms: number | undefined): string {
  if (ms === undefined) return 'unknown time';
  return `${new Date(ms).toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

export function minutes(windowMinutes: number): string {
  return windowMinutes === 1 ? '1 minute' : `${windowMinutes} minutes`;
}

export function plural(n: number, singular: string, pluralForm = `${singular}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? singular : pluralForm}`;
}

/** Comma-separated preview of values, e.g. "root, admin, test (+4 more)". */
export function listPreview(values: string[], max = 5): string {
  if (values.length === 0) return 'none';
  const shown = values.slice(0, max).join(', ');
  return values.length > max ? `${shown} (+${values.length - max} more)` : shown;
}

export function unique<T>(values: Iterable<T | undefined>): T[] {
  const out = new Set<T>();
  for (const v of values) if (v !== undefined) out.add(v);
  return [...out];
}

/** Event ids in ascending order with no duplicates. */
export function uniqueIds(ids: Iterable<number>): number[] {
  return [...new Set(ids)].sort((a, b) => a - b);
}

/** First, peak and last timestamps, deduplicated. */
export function representative(start: number, peakAt: number, end: number): number[] {
  return [...new Set([start, peakAt, end])].sort((a, b) => a - b);
}
