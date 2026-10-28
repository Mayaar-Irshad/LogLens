import {
  SEVERITY_RANK,
  type Confidence,
  type Detection,
  type EntityRisk,
  type RuleId,
  type Severity,
} from '../../../types/detection';

/**
 * Deterministic, documented risk scoring. Scores order findings for review;
 * they are not probabilities and do not indicate confirmed compromise.
 *
 *   score = base(severity) + confidence adjustment + volume bonus, clamped 0–100
 *   volume bonus = min(12, round(4 × log2(metric / threshold)))  (0 when at threshold)
 */
export const SEVERITY_BASE: Record<Severity, number> = {
  critical: 90,
  high: 72,
  medium: 50,
  low: 28,
  info: 10,
};

export const CONFIDENCE_ADJUSTMENT: Record<Confidence, number> = {
  high: 8,
  medium: 0,
  low: -8,
};

export function volumeBonus(metric: number, threshold: number): number {
  if (!(threshold > 0) || !(metric > threshold)) return 0;
  return Math.min(12, Math.round(4 * Math.log2(metric / threshold)));
}

export function scoreFinding(
  severity: Severity,
  confidence: Confidence,
  metric: number,
  threshold: number,
): number {
  const raw =
    SEVERITY_BASE[severity] + CONFIDENCE_ADJUSTMENT[confidence] + volumeBonus(metric, threshold);
  return Math.max(0, Math.min(100, raw));
}

/** Additional points per extra distinct rule implicating the same entity. */
export const MULTI_RULE_BONUS = 6;

/**
 * Aggregate risk per IP and account, based on the detections whose subject
 * they are. The entity score is the highest detection score plus a bonus for
 * each additional distinct rule.
 */
export function assessEntities(detections: readonly Detection[]): EntityRisk[] {
  const map = new Map<string, EntityRisk & { best: number; rules: Set<RuleId> }>();
  const add = (kind: 'ip' | 'user', value: string, d: Detection): void => {
    const key = `${kind}:${value}`;
    let entry = map.get(key);
    if (!entry) {
      entry = {
        kind,
        value,
        score: 0,
        best: 0,
        maxSeverity: 'info',
        ruleIds: [],
        detectionIds: [],
        eventCount: 0,
        rules: new Set(),
      };
      map.set(key, entry);
    }
    entry.best = Math.max(entry.best, d.riskScore);
    if (SEVERITY_RANK[d.severity] > SEVERITY_RANK[entry.maxSeverity])
      entry.maxSeverity = d.severity;
    entry.rules.add(d.ruleId);
    entry.detectionIds.push(d.id);
    entry.eventCount += d.matchedEventCount;
  };
  for (const d of detections) {
    if (d.ruleId === 'GEN-003') continue; // correlation is already reflected by the multi-rule bonus
    for (const ip of d.subjects.ips) add('ip', ip, d);
    for (const user of d.subjects.users) add('user', user, d);
  }
  return [...map.values()]
    .map(({ best, rules, ...e }) => ({
      ...e,
      ruleIds: [...rules].sort(),
      score: Math.min(100, best + MULTI_RULE_BONUS * (rules.size - 1)),
    }))
    .sort(
      (a, b) => b.score - a.score || b.eventCount - a.eventCount || (a.value < b.value ? -1 : 1),
    );
}

export type PostureLevel = 'none' | 'informational' | 'low' | 'elevated' | 'high' | 'critical';

export interface Posture {
  level: PostureLevel;
  counts: Record<Severity, number>;
  summary: string;
}

/** Summarize the highest finding severity; worded to avoid implying confirmed incidents. */
export function assessPosture(detections: readonly Detection[]): Posture {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const d of detections) counts[d.severity]++;
  let level: PostureLevel = 'none';
  if (counts.critical > 0) level = 'critical';
  else if (counts.high > 0) level = 'high';
  else if (counts.medium > 0) level = 'elevated';
  else if (counts.low > 0) level = 'low';
  else if (counts.info > 0) level = 'informational';
  const summaries: Record<PostureLevel, string> = {
    none: 'No detection rules triggered for this data with the current thresholds.',
    informational: 'Only informational findings. Review them for context.',
    low: 'Low-severity findings only. Review when convenient.',
    elevated: 'Medium-severity findings warrant review.',
    high: 'High-severity findings should be reviewed promptly.',
    critical:
      'Critical-priority findings: verify them first. Findings are leads, not confirmed incidents.',
  };
  return { level, counts, summary: summaries[level] };
}
