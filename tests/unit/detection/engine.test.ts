import { describe, expect, it } from 'vitest';
import {
  defaultDetectionConfig,
  validateDetectionConfig,
} from '../../../src/features/detection/config/detectionConfig';
import {
  MAX_FINDINGS_PER_RULE,
  runDetections,
} from '../../../src/features/detection/engine/runDetections';
import {
  baselineBucketMs,
  MAX_BASELINE_BUCKETS,
  median,
} from '../../../src/features/detection/rules/general';
import { RULE_INFO, RULES, getRule } from '../../../src/features/detection/rules/registry';
import {
  assessEntities,
  assessPosture,
  scoreFinding,
  volumeBonus,
} from '../../../src/features/detection/risk/risk';
import type { ParseStats } from '../../../src/types/ingestion';
import { build, fail, MIN, ok, req, SEC, T0, times } from '../../helpers/events';
import { runOnly } from '../../helpers/detection';

const ATTACKER = '203.0.113.50';

const stats = (overrides: Partial<ParseStats>): ParseStats => ({
  totalLines: 0,
  blankLines: 0,
  skippedLines: 0,
  parsedRecords: 0,
  partialRecords: 0,
  rejectedRecords: 0,
  eventsCreated: 0,
  expandedRepeats: 0,
  duplicateLines: 0,
  unprocessedLines: 0,
  eventsWithoutTimestamp: 0,
  bytesRead: 0,
  warnings: [],
  ...overrides,
});

describe('rule registry', () => {
  it('defines at least the required rules with complete explanations', () => {
    expect(RULES.map((r) => r.id)).toEqual([
      'AUTH-001',
      'AUTH-002',
      'AUTH-003',
      'AUTH-004',
      'AUTH-005',
      'AUTH-006',
      'AUTH-007',
      'WEB-001',
      'WEB-002',
      'WEB-003',
      'WEB-004',
      'WEB-005',
      'WEB-006',
      'WEB-007',
      'WEB-008',
      'WEB-009',
      'GEN-001',
      'GEN-002',
      'GEN-003',
    ]);
    for (const r of RULE_INFO) {
      expect(r.description.length).toBeGreaterThan(40);
      expect(r.recommendations.length).toBeGreaterThan(0);
      expect(r.limitations.length).toBeGreaterThan(0);
      expect(r.falsePositives.length).toBeGreaterThan(0);
      for (const p of r.params) expect(p.default).toBeGreaterThanOrEqual(p.min);
    }
    expect(() => getRule('NOPE-1' as never)).toThrow();
    expect(getRule('AUTH-004').scope).toBe('ip-user');
  });
});

describe('detection configuration', () => {
  it('clamps untrusted values and drops unknown keys', () => {
    const cfg = validateDetectionConfig({
      rules: {
        'AUTH-001': { enabled: false, params: { threshold: -5, windowMinutes: '30', bogus: 1 } },
        'WEB-006': { params: { threshold: 1e12 } },
        'XSS-<script>': { enabled: true },
        __proto__: { enabled: false },
      },
    });
    expect(cfg.rules['AUTH-001']).toEqual({
      enabled: false,
      params: { threshold: 2, windowMinutes: 30 },
    });
    expect(cfg.rules['WEB-006'].params.threshold).toBe(100_000);
    expect(cfg.rules['WEB-006'].enabled).toBe(true);
    expect(Object.keys(cfg.rules)).toHaveLength(RULES.length);
    expect(validateDetectionConfig('garbage')).toEqual(defaultDetectionConfig());
  });
});

describe('runDetections', () => {
  const attack = build([
    ...times(12, T0, 10 * SEC).map((t) => fail(t, ATTACKER, 'root')),
    ok(T0 + 3 * MIN, ATTACKER, 'root'),
    ...times(20, T0, 30 * SEC).map((t) => ok(t + 7 * SEC, '192.0.2.10', 'alice')),
  ]);

  it('returns nothing for an empty dataset and explains why rules did not run', () => {
    const run = runDetections([], defaultDetectionConfig());
    expect(run.detections).toEqual([]);
    expect(run.ruleRuns).toHaveLength(RULES.length);
    expect(run.ruleRuns.filter((r) => r.ruleId !== 'GEN-003').every((r) => !r.evaluated)).toBe(
      true,
    );
  });

  it('produces no detections for benign activity', () => {
    const benign = build([
      ...times(30, T0, 5 * MIN).map((t, i) => ok(t, `192.0.2.${i % 5}`, `user${i % 5}`)),
      fail(T0 + 2 * MIN, '192.0.2.1', 'user1'),
      ...times(100, T0, 30 * SEC).map((t, i) =>
        req(t, `198.51.100.${i % 10}`, `/page/${i % 7}`, 200),
      ),
    ]);
    expect(runDetections(benign, defaultDetectionConfig()).detections).toEqual([]);
  });

  it('is deterministic: identical input yields identical ids and order', () => {
    const a = runDetections(attack, defaultDetectionConfig(), { now: () => 0 });
    const b = runDetections(attack, defaultDetectionConfig(), { now: () => 0 });
    expect(a.detections.map((d) => d.id)).toEqual(b.detections.map((d) => d.id));
    expect(a).toEqual(b);
  });

  it('correlates indicators across rules (GEN-003) and sorts by severity', () => {
    const { detections } = runDetections(attack, defaultDetectionConfig());
    const ids = detections.map((d) => d.ruleId);
    expect(ids).toEqual(expect.arrayContaining(['AUTH-001', 'AUTH-004', 'GEN-003']));
    const corr = detections.find(
      (d) => d.ruleId === 'GEN-003' && d.subjects.ips.includes(ATTACKER),
    )!;
    expect(corr.severity).toBe('critical');
    expect(corr.relatedDetectionIds).toHaveLength(2);
    expect(corr.reason).toContain('possible account compromise');
    expect(detections[0]?.severity).toBe('critical');
  });

  it('skips disabled rules and records them', () => {
    const cfg = defaultDetectionConfig();
    cfg.rules['AUTH-001'].enabled = false;
    const run = runDetections(attack, cfg);
    expect(run.detections.some((d) => d.ruleId === 'AUTH-001')).toBe(false);
    expect(run.ruleRuns.find((r) => r.ruleId === 'AUTH-001')).toMatchObject({
      enabled: false,
      note: 'Disabled in settings.',
    });
  });

  it('caps findings per rule and keeps the strongest', () => {
    // One TRACE request from each of 505 distinct clients → 505 findings, capped at 500.
    const events = build(
      Array.from({ length: MAX_FINDINGS_PER_RULE + 5 }, (_, i) =>
        req(T0 + i, `2001:db8::${(i + 1).toString(16)}`, '/', 405, { method: 'TRACE' }),
      ),
    );
    const run = runOnly('WEB-005', events);
    expect(run.detections).toHaveLength(MAX_FINDINGS_PER_RULE);
    expect(run.ruleRuns.find((r) => r.ruleId === 'WEB-005')?.note).toContain(
      '5 weaker finding(s) omitted',
    );
  });

  it('includes the explanation fields required for every detection', () => {
    const { detections } = runDetections(attack, defaultDetectionConfig());
    for (const d of detections) {
      expect(d.reason.length).toBeGreaterThan(20);
      expect(d.condition.length).toBeGreaterThan(10);
      expect(d.thresholds.length).toBeGreaterThan(0);
      expect(d.recommendations.length).toBeGreaterThan(0);
      expect(d.limitations.length).toBeGreaterThan(0);
      expect(d.falsePositives.length).toBeGreaterThan(0);
      expect(d.matchedEventCount).toBe(d.eventIds.length);
      expect(d.riskScore).toBeGreaterThanOrEqual(0);
      expect(d.riskScore).toBeLessThanOrEqual(100);
      expect(d.categories).toContain('authentication');
    }
  });
});

describe('GEN-001 malformed records', () => {
  it('fires when enough records are rejected or partial', () => {
    const events = build([
      { category: 'other', action: 'x', status: 'partial', issues: ['invalid timestamp: x'] },
    ]);
    const run = runDetections(events, defaultDetectionConfig(), {
      stats: stats({ parsedRecords: 90, partialRecords: 1, rejectedRecords: 9 }),
    });
    const d = run.detections.find((x) => x.ruleId === 'GEN-001');
    expect(d).toMatchObject({
      severity: 'info',
      eventIds: [0],
      title: '10% of records were malformed or incomplete',
    });
  });

  it('stays quiet below the thresholds and rates heavy damage higher', () => {
    const quiet = runDetections([], defaultDetectionConfig(), {
      stats: stats({ parsedRecords: 1000, rejectedRecords: 9 }),
    });
    expect(quiet.detections).toHaveLength(0);
    const heavy = runDetections([], defaultDetectionConfig(), {
      stats: stats({ parsedRecords: 50, rejectedRecords: 50 }),
    });
    expect(heavy.detections[0]?.severity).toBe('low');
    expect(
      runDetections([], defaultDetectionConfig(), { stats: stats({}) }).detections,
    ).toHaveLength(0);
  });
});

describe('GEN-002 volume spike against baseline', () => {
  it('flags a bucket far above the median', () => {
    const steady = Array.from({ length: 24 }, (_, b) =>
      times(5, T0 + b * 5 * MIN, 30 * SEC),
    ).flat();
    const spike = times(60, T0 + 12 * 5 * MIN + 2 * SEC, 2 * SEC);
    const events = build(
      [...steady, ...spike]
        .sort((a, b) => a - b)
        .map((t) => ({ category: 'system', action: 'x', timestamp: t })),
    );
    const [d] = runOnly('GEN-002', events).detections;
    expect(d?.metric).toBe(65);
    expect(d?.thresholds.find((t) => t.name === 'Computed spike threshold')?.value).toBe(20);
    expect(d?.severity).toBe('medium');
  });

  it('reports insufficient data instead of guessing', () => {
    const events = build(
      times(100, T0, SEC).map((t) => ({ category: 'system' as const, action: 'x', timestamp: t })),
    );
    const run = runOnly('GEN-002', events);
    expect(run.detections).toHaveLength(0);
    expect(run.ruleRuns.find((r) => r.ruleId === 'GEN-002')?.note).toMatch(/Insufficient data/);
  });

  it('computes medians and widens buckets for long spans', () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 2, 3])).toBe(2.5);
    expect(median([])).toBe(0);
    expect(baselineBucketMs(60 * MIN, 5)).toBe(5 * MIN);
    const year = 365 * 24 * 60 * MIN;
    expect(year / baselineBucketMs(year, 5)).toBeLessThan(MAX_BASELINE_BUCKETS);
  });
});

describe('risk assessment', () => {
  it('scores by severity, confidence and volume', () => {
    expect(scoreFinding('medium', 'medium', 10, 10)).toBe(50);
    expect(scoreFinding('high', 'high', 40, 10)).toBe(72 + 8 + 8);
    expect(scoreFinding('critical', 'high', 1e9, 1)).toBe(100);
    expect(scoreFinding('info', 'low', 1, 1)).toBe(2);
    expect(volumeBonus(5, 10)).toBe(0);
    expect(volumeBonus(10, 0)).toBe(0);
  });

  it('aggregates entities and rewards multiple independent rules', () => {
    const { detections } = runDetections(
      build([
        ...times(12, T0, 10 * SEC).map((t) => fail(t, ATTACKER, 'root')),
        ok(T0 + 3 * MIN, ATTACKER, 'root'),
      ]),
      defaultDetectionConfig(),
    );
    const entities = assessEntities(detections);
    const ip = entities.find((e) => e.kind === 'ip' && e.value === ATTACKER)!;
    const best = Math.max(
      ...detections
        .filter((d) => d.subjects.ips.includes(ATTACKER) && d.ruleId !== 'GEN-003')
        .map((d) => d.riskScore),
    );
    expect(ip.ruleIds).toEqual(['AUTH-001', 'AUTH-004']);
    expect(ip.score).toBe(Math.min(100, best + 6));
    expect(entities.find((e) => e.kind === 'user')?.value).toBe('root');
  });

  it('summarizes posture without claiming incidents', () => {
    expect(assessPosture([]).level).toBe('none');
    const { detections } = runDetections(
      build(times(10, T0, SEC).map((t) => fail(t, ATTACKER, 'root'))),
      defaultDetectionConfig(),
    );
    const posture = assessPosture(detections);
    expect(posture.level).toBe('elevated');
    expect(posture.counts.medium).toBeGreaterThan(0);
  });
});
