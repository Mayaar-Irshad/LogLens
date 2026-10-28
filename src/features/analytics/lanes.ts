import type { NormalizedEvent } from '../../types/events';

export interface LaneKey {
  kind: 'ip' | 'user';
  value: string;
}

export interface LaneCell {
  total: number;
  /** Failed logins, failed privilege use and HTTP responses of 400 or higher. */
  risky: number;
}

export interface Lane extends LaneKey {
  total: number;
  risky: number;
  first?: number;
  last?: number;
  cells: LaneCell[];
}

export interface LanesResult {
  start: number;
  end: number;
  bucketMs: number;
  lanes: Lane[];
}

export const MAX_LANES = 12;
export const MAX_CELLS = 240;

export function isRisky(e: NormalizedEvent): boolean {
  if (
    e.auth?.outcome === 'failure' &&
    (e.category === 'authentication' || e.category === 'privilege')
  ) {
    return true;
  }
  return e.http?.status !== undefined && e.http.status >= 400;
}

/**
 * Activity per indicator over one shared time axis: for each IP or account,
 * event counts in equal cells spanning the selected events' time range. Used
 * by the overview's indicator strip; events without timestamps are counted in
 * the lane total but not placed on the axis.
 */
export function computeLanes(
  events: readonly NormalizedEvent[],
  ids: readonly number[] | null,
  keys: readonly LaneKey[],
  cellCount: number,
): LanesResult {
  const cells = Math.max(1, Math.min(MAX_CELLS, Math.floor(cellCount) || 72));
  const lanes: Lane[] = keys.slice(0, MAX_LANES).map((k) => ({
    kind: k.kind,
    value: k.value,
    total: 0,
    risky: 0,
    cells: Array.from({ length: cells }, () => ({ total: 0, risky: 0 })),
  }));
  const byIp = new Map<string, Lane[]>();
  const byUser = new Map<string, Lane[]>();
  for (const lane of lanes) {
    const map = lane.kind === 'ip' ? byIp : byUser;
    map.set(lane.value, [...(map.get(lane.value) ?? []), lane]);
  }

  let start = Infinity;
  let end = -Infinity;
  const each = (fn: (e: NormalizedEvent) => void): void => {
    if (ids === null) for (const e of events) fn(e);
    else for (const id of ids) fn(events[id]!);
  };
  each((e) => {
    if (e.timestamp === undefined) return;
    if (e.timestamp < start) start = e.timestamp;
    if (e.timestamp > end) end = e.timestamp;
  });
  if (start === Infinity) return { start: 0, end: 0, bucketMs: 0, lanes };
  const bucketMs = Math.max(1, Math.ceil((end - start + 1) / cells));

  each((e) => {
    const matched = [
      ...(e.sourceIp ? (byIp.get(e.sourceIp) ?? []) : []),
      ...(e.username ? (byUser.get(e.username) ?? []) : []),
    ];
    if (matched.length === 0) return;
    const risky = isRisky(e);
    for (const lane of matched) {
      lane.total++;
      if (risky) lane.risky++;
      if (e.timestamp === undefined) continue;
      const cell = lane.cells[Math.min(cells - 1, Math.floor((e.timestamp - start) / bucketMs))]!;
      cell.total++;
      if (risky) cell.risky++;
      if (lane.first === undefined || e.timestamp < lane.first) lane.first = e.timestamp;
      if (lane.last === undefined || e.timestamp > lane.last) lane.last = e.timestamp;
    }
  });
  return { start, end, bucketMs, lanes };
}
