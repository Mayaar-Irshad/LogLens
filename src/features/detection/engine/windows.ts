/**
 * Sliding-window primitives used by threshold rules.
 *
 * A *burst* is a maximal run of items in which every item belongs to at least
 * one window of length `windowMs` containing `threshold` or more items.
 * Overlapping qualifying windows are merged into one burst, so a sustained
 * attack produces one detection rather than one per window.
 *
 * Windows are inclusive: items at t and t + windowMs are in the same window.
 */

export interface TimedRef {
  t: number;
  id: number;
}

export interface Burst {
  start: number;
  end: number;
  /** Items in the burst. */
  count: number;
  /** Largest number of items (or distinct keys) observed in a single window. */
  peak: number;
  /** End time of the window where the peak occurred. */
  peakAt: number;
  ids: number[];
}

/** Sort timed references ascending by time, then id (stable and deterministic). */
export function sortTimed<T extends TimedRef>(items: T[]): T[] {
  return items.sort((a, b) => a.t - b.t || a.id - b.id);
}

interface Open {
  startIdx: number;
  endIdx: number;
  peak: number;
  peakAt: number;
}

function close<T extends TimedRef>(items: T[], open: Open): Burst {
  const slice = items.slice(open.startIdx, open.endIdx + 1);
  return {
    start: slice[0]!.t,
    end: slice[slice.length - 1]!.t,
    count: slice.length,
    peak: open.peak,
    peakAt: open.peakAt,
    ids: slice.map((i) => i.id),
  };
}

/** Bursts where at least `threshold` items fall within `windowMs`. Items must be sorted. */
export function findBursts<T extends TimedRef>(
  items: T[],
  windowMs: number,
  threshold: number,
): Burst[] {
  const bursts: Burst[] = [];
  if (threshold < 1 || items.length < threshold) return bursts;
  let left = 0;
  let open: Open | null = null;
  for (let right = 0; right < items.length; right++) {
    const t = items[right]!.t;
    while (t - items[left]!.t > windowMs) left++;
    const count = right - left + 1;
    if (count < threshold) continue;
    if (open && left <= open.endIdx) {
      open.endIdx = right;
      if (count > open.peak) {
        open.peak = count;
        open.peakAt = t;
      }
    } else {
      if (open) bursts.push(close(items, open));
      open = { startIdx: left, endIdx: right, peak: count, peakAt: t };
    }
  }
  if (open) bursts.push(close(items, open));
  return bursts;
}

/**
 * Bursts where at least `minDistinct` distinct keys (e.g. usernames or paths)
 * occur within `windowMs`. Items must be sorted.
 */
export function findDistinctBursts<T extends TimedRef & { key: string }>(
  items: T[],
  windowMs: number,
  minDistinct: number,
): Burst[] {
  const bursts: Burst[] = [];
  if (minDistinct < 1) return bursts;
  const counts = new Map<string, number>();
  let left = 0;
  let open: Open | null = null;
  for (let right = 0; right < items.length; right++) {
    const item = items[right]!;
    counts.set(item.key, (counts.get(item.key) ?? 0) + 1);
    while (item.t - items[left]!.t > windowMs) {
      const k = items[left]!.key;
      const n = (counts.get(k) ?? 1) - 1;
      if (n === 0) counts.delete(k);
      else counts.set(k, n);
      left++;
    }
    const distinct = counts.size;
    if (distinct < minDistinct) continue;
    if (open && left <= open.endIdx) {
      open.endIdx = right;
      if (distinct > open.peak) {
        open.peak = distinct;
        open.peakAt = item.t;
      }
    } else {
      if (open) bursts.push(close(items, open));
      open = { startIdx: left, endIdx: right, peak: distinct, peakAt: item.t };
    }
  }
  if (open) bursts.push(close(items, open));
  return bursts;
}

/** Group items by a key, skipping items whose key is undefined. Preserves order. */
export function groupBy<T>(
  items: readonly T[],
  key: (item: T) => string | undefined,
): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (k === undefined) continue;
    let list = out.get(k);
    if (!list) {
      list = [];
      out.set(k, list);
    }
    list.push(item);
  }
  return out;
}

/** Index of the first element with t >= target in a sorted array. */
export function lowerBound(items: readonly TimedRef[], target: number): number {
  let lo = 0;
  let hi = items.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (items[mid]!.t < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Count occurrences and return the top entries, ties broken by key. */
export function topCounts(
  values: Iterable<string | undefined>,
  limit: number,
): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const v of values) if (v !== undefined) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .slice(0, limit);
}
