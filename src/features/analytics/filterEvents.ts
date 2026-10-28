import type { DisplayTimeZone, EventFilter, StatusClass } from '../../types/analytics';
import type { NormalizedEvent } from '../../types/events';
import type { DetectionIndex } from './detectionIndex';

export function hourOf(ms: number, tz: DisplayTimeZone): number {
  const d = new Date(ms);
  return tz === 'UTC' ? d.getUTCHours() : d.getHours();
}

export function statusClassOf(status: number | undefined): StatusClass | undefined {
  if (status === undefined) return undefined;
  const c = Math.floor(status / 100);
  return c >= 1 && c <= 5 ? (`${c}xx` as StatusClass) : undefined;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const setOf = <T>(values: readonly T[] | undefined): Set<T> | null =>
  values && values.length > 0 ? new Set(values) : null;

/** True when the filter constrains events (anything beyond an empty filter). */
export function hasEventConstraints(filter: EventFilter): boolean {
  const { timeZone: _tz, ...rest } = filter;
  return Object.values(rest).some((v) => {
    if (v === undefined || v === null || v === '') return false;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') return Object.values(v as object).some((x) => x !== undefined);
    return true;
  });
}

/**
 * Compile a filter into a predicate. All active constraints must match (AND);
 * values within one constraint are alternatives (OR). When a time range is
 * active, events without a timestamp do not match, because their time is
 * unknown.
 */
export function compileFilter(
  filter: EventFilter,
  index?: DetectionIndex,
): (e: NormalizedEvent) => boolean {
  const tz = filter.timeZone ?? 'UTC';
  const start = filter.timeRange?.start;
  const end = filter.timeRange?.end;
  const ips = setOf(filter.sourceIps);
  const users = setOf(filter.usernames);
  const categories = setOf(filter.categories);
  const actions = setOf(filter.actions);
  const outcomes = setOf(filter.authOutcomes);
  const methods = setOf(filter.httpMethods);
  const statuses = setOf(filter.httpStatuses);
  const classes = setOf(filter.statusClasses);
  const paths = setOf(filter.paths);
  const hours = setOf(filter.hours);
  const parse = setOf(filter.parseStatuses);
  const formats = setOf(filter.formats);
  const detectionFilter = filter.detectionIds
    ? (index?.resolve(filter.detectionIds) ?? new Set<number>())
    : null;
  const query = filter.search?.trim();
  const search = query ? new RegExp(escapeRegExp(query.slice(0, 200)), 'i') : null;

  return (e) => {
    if (start !== undefined || end !== undefined) {
      if (e.timestamp === undefined) return false;
      if (start !== undefined && e.timestamp < start) return false;
      if (end !== undefined && e.timestamp > end) return false;
    }
    if (ips && (e.sourceIp === undefined || !ips.has(e.sourceIp))) return false;
    if (users && (e.username === undefined || !users.has(e.username))) return false;
    if (categories && !categories.has(e.category)) return false;
    if (actions && !actions.has(e.action)) return false;
    // Same definition as the authentication counters: outcomes of authentication events only.
    if (
      outcomes &&
      (e.category !== 'authentication' ||
        e.auth?.outcome === undefined ||
        !outcomes.has(e.auth.outcome))
    )
      return false;
    if (methods && (e.http?.method === undefined || !methods.has(e.http.method))) return false;
    if (statuses && (e.http?.status === undefined || !statuses.has(e.http.status))) return false;
    if (classes) {
      const c = statusClassOf(e.http?.status);
      if (c === undefined || !classes.has(c)) return false;
    }
    if (paths && (e.http?.path === undefined || !paths.has(e.http.path))) return false;
    if (hours && (e.timestamp === undefined || !hours.has(hourOf(e.timestamp, tz)))) return false;
    if (parse && !parse.has(e.status)) return false;
    if (formats && !formats.has(e.format)) return false;
    if (detectionFilter) {
      const linked = index?.detectionsFor(e.id) ?? [];
      if (!linked.some((i) => detectionFilter.has(i))) return false;
    }
    if (search && !search.test(e.raw)) return false;
    return true;
  };
}

/** Ids of matching events, in dataset order. */
export function filterEventIds(
  events: readonly NormalizedEvent[],
  filter: EventFilter,
  index?: DetectionIndex,
): number[] {
  const predicate = compileFilter(filter, index);
  const out: number[] = [];
  for (const e of events) if (predicate(e)) out.push(e.id);
  return out;
}

/**
 * Detections "in scope" for a filtered event set: those with at least one
 * supporting event in the set. Returns null when the filter has no event
 * constraints (every detection is in scope).
 */
export function detectionsInScope(
  matchingIds: readonly number[],
  filter: EventFilter,
  index: DetectionIndex,
): string[] | null {
  if (!hasEventConstraints(filter)) return null;
  const hit = new Set<number>();
  for (const id of matchingIds) for (const i of index.detectionsFor(id)) hit.add(i);
  return [...hit].sort((a, b) => a - b).map((i) => index.detections[i]!.id);
}
