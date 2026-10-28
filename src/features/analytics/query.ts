import type { EventPage, EventRow, EventSort, RelatedBy } from '../../types/analytics';
import type { NormalizedEvent } from '../../types/events';
import type { DetectionIndex } from './detectionIndex';

export const MAX_PAGE_SIZE = 200;

const compareStrings = (a: string | undefined, b: string | undefined): number => {
  if (a === b) return 0;
  if (a === undefined) return 1;
  if (b === undefined) return -1;
  return a < b ? -1 : 1;
};

const compareNumbers = (a: number | undefined, b: number | undefined): number => {
  if (a === b) return 0;
  if (a === undefined) return 1;
  if (b === undefined) return -1;
  return a - b;
};

/**
 * Sort event ids without touching the underlying events. Missing values sort
 * last in both directions so that sorting never hides records; ties fall back
 * to the original line order for stability.
 */
export function sortEventIds(
  events: readonly NormalizedEvent[],
  ids: readonly number[],
  sort: EventSort,
): number[] {
  const dir = sort.direction === 'asc' ? 1 : -1;
  const key = (e: NormalizedEvent): string | number | undefined => {
    switch (sort.field) {
      case 'timestamp':
        return e.timestamp;
      case 'line':
        return e.line;
      case 'sourceIp':
        return e.sourceIp;
      case 'username':
        return e.username;
      case 'action':
        return e.action;
      case 'status':
        return e.http?.status;
    }
  };
  return [...ids].sort((ia, ib) => {
    const a = events[ia]!;
    const b = events[ib]!;
    const ka = key(a);
    const kb = key(b);
    let c: number;
    if (ka === undefined || kb === undefined) c = ka === kb ? 0 : ka === undefined ? 1 : -1;
    else
      c =
        (typeof ka === 'number'
          ? compareNumbers(ka, kb as number)
          : compareStrings(ka, kb as string)) * dir;
    return c || a.id - b.id;
  });
}

export function toRow(e: NormalizedEvent, index?: DetectionIndex): EventRow {
  const maxSeverity = index?.maxSeverity(e.id);
  return {
    ...e,
    detectionIds: index?.detectionIdsFor(e.id) ?? [],
    ...(maxSeverity ? { maxSeverity } : {}),
  };
}

export function pageOf(
  events: readonly NormalizedEvent[],
  ids: readonly number[],
  page: number,
  pageSize: number,
  index?: DetectionIndex,
): EventPage {
  const size = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(pageSize) || 50));
  const pages = Math.max(1, Math.ceil(ids.length / size));
  const p = Math.min(Math.max(0, Math.floor(page) || 0), pages - 1);
  const rows = ids.slice(p * size, p * size + size).map((id) => toRow(events[id]!, index));
  return { rows, total: ids.length, page: p, pageSize: size };
}

export interface RelatedResult {
  anchorId: number;
  by: RelatedBy;
  /** Human-readable description of the relation, e.g. "same source IP 192.0.2.1". */
  description: string;
  page: EventPage;
}

/**
 * Events related to an anchor event: same source IP, same username, or within
 * ±windowMinutes of its timestamp. Results are chronological.
 */
export function relatedEvents(
  events: readonly NormalizedEvent[],
  anchorId: number,
  by: RelatedBy,
  windowMinutes: number,
  limit: number,
  index?: DetectionIndex,
): RelatedResult {
  const anchor = events[anchorId];
  const empty = (description: string): RelatedResult => ({
    anchorId,
    by,
    description,
    page: { rows: [], total: 0, page: 0, pageSize: limit },
  });
  if (!anchor) return empty('Event not found.');
  let predicate: (e: NormalizedEvent) => boolean;
  let description: string;
  if (by === 'ip') {
    if (!anchor.sourceIp) return empty('This event has no source IP.');
    predicate = (e) => e.sourceIp === anchor.sourceIp;
    description = `same source IP ${anchor.sourceIp}`;
  } else if (by === 'user') {
    if (!anchor.username) return empty('This event has no username.');
    predicate = (e) => e.username === anchor.username;
    description = `same username ${anchor.username}`;
  } else {
    if (anchor.timestamp === undefined) return empty('This event has no timestamp.');
    const w = Math.max(1, Math.min(1440, windowMinutes)) * 60_000;
    const t = anchor.timestamp;
    predicate = (e) => e.timestamp !== undefined && Math.abs(e.timestamp - t) <= w;
    description = `within ±${Math.max(1, Math.min(1440, windowMinutes))} min of the event`;
  }
  const ids: number[] = [];
  for (const e of events) if (e.id !== anchorId && predicate(e)) ids.push(e.id);
  const sorted = sortEventIds(events, ids, { field: 'timestamp', direction: 'asc' });
  return { anchorId, by, description, page: pageOf(events, sorted, 0, limit, index) };
}
