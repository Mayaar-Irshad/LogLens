import { describe, expect, it } from 'vitest';
import {
  findBursts,
  findDistinctBursts,
  groupBy,
  lowerBound,
  sortTimed,
  topCounts,
} from '../../../src/features/detection/engine/windows';

const refs = (ts: number[]) => ts.map((t, id) => ({ t, id }));

describe('findBursts', () => {
  it('fires exactly at the threshold and not below it', () => {
    expect(findBursts(refs([0, 1, 2]), 10, 3)).toHaveLength(1);
    expect(findBursts(refs([0, 1]), 10, 3)).toHaveLength(0);
  });

  it('treats the window as inclusive', () => {
    expect(findBursts(refs([0, 5, 10]), 10, 3)).toHaveLength(1);
    expect(findBursts(refs([0, 5, 11]), 10, 3)).toHaveLength(0);
  });

  it('merges overlapping windows into one burst with all qualifying items', () => {
    const [b] = findBursts(refs([0, 1, 2, 3, 4, 5, 6]), 2, 3);
    expect(b).toMatchObject({ start: 0, end: 6, count: 7, peak: 3 });
  });

  it('separates bursts that do not share any item', () => {
    const bursts = findBursts(refs([0, 1, 2, 100, 101, 102]), 5, 3);
    expect(bursts.map((b) => b.ids)).toEqual([
      [0, 1, 2],
      [3, 4, 5],
    ]);
  });

  it('excludes leading items that are not part of any qualifying window', () => {
    const [b] = findBursts(refs([0, 50, 51, 52]), 5, 3);
    expect(b?.ids).toEqual([1, 2, 3]);
  });

  it('records the peak count and when it occurred', () => {
    const [b] = findBursts(refs([0, 1, 2, 3, 9]), 3, 3);
    expect(b).toMatchObject({ peak: 4, peakAt: 3 });
  });

  it('ignores invalid thresholds', () => {
    expect(findBursts(refs([0, 1]), 10, 0)).toEqual([]);
  });
});

describe('findDistinctBursts', () => {
  const items = (pairs: Array<[number, string]>) => pairs.map(([t, key], id) => ({ t, id, key }));

  it('counts distinct keys, not items', () => {
    expect(
      findDistinctBursts(
        items([
          [0, 'a'],
          [1, 'a'],
          [2, 'a'],
          [3, 'b'],
        ]),
        10,
        3,
      ),
    ).toEqual([]);
    const [b] = findDistinctBursts(
      items([
        [0, 'a'],
        [1, 'b'],
        [2, 'a'],
        [3, 'c'],
      ]),
      10,
      3,
    );
    expect(b).toMatchObject({ count: 4, peak: 3 });
  });

  it('expires keys that leave the window', () => {
    expect(
      findDistinctBursts(
        items([
          [0, 'a'],
          [20, 'b'],
          [40, 'c'],
        ]),
        10,
        2,
      ),
    ).toEqual([]);
  });

  it('returns nothing for a non-positive minimum', () => {
    expect(findDistinctBursts(items([[0, 'a']]), 10, 0)).toEqual([]);
  });
});

describe('helpers', () => {
  it('sorts deterministically by time then id', () => {
    expect(
      sortTimed([
        { t: 2, id: 1 },
        { t: 1, id: 5 },
        { t: 1, id: 2 },
      ]),
    ).toEqual([
      { t: 1, id: 2 },
      { t: 1, id: 5 },
      { t: 2, id: 1 },
    ]);
  });

  it('finds lower bounds', () => {
    const r = refs([1, 3, 3, 7]);
    expect([0, 1, 3, 4, 8].map((t) => lowerBound(r, t))).toEqual([0, 0, 1, 3, 4]);
  });

  it('groups by key and drops undefined keys', () => {
    const g = groupBy([{ k: 'a' }, { k: undefined }, { k: 'a' }, { k: 'b' }], (x) => x.k);
    expect([...g].map(([k, v]) => [k, v.length])).toEqual([
      ['a', 2],
      ['b', 1],
    ]);
  });

  it('ranks top counts with deterministic tie-breaking', () => {
    expect(topCounts(['b', 'a', 'b', 'c', 'a', undefined], 2)).toEqual([
      { key: 'a', count: 2 },
      { key: 'b', count: 2 },
    ]);
  });
});
