import {
  SEVERITY_RANK,
  type Detection,
  type DetectionConfig,
  type RuleId,
} from '../../../types/detection';
import type { EventCategory, NormalizedEvent } from '../../../types/events';
import type { ParseStats } from '../../../types/ingestion';
import { shortHash } from '../../../utils/hash';
import { validateDetectionConfig } from '../config/detectionConfig';
import { scoreFinding } from '../risk/risk';
import { RULES } from '../rules/registry';
import { buildDetectionContext } from './context';
import type { DetectionContext, Finding, RuleDefinition } from './types';

/** Findings kept per rule; the strongest are retained when a rule produces more. */
export const MAX_FINDINGS_PER_RULE = 500;

export interface RuleRun {
  ruleId: RuleId;
  name: string;
  enabled: boolean;
  evaluated: boolean;
  findings: number;
  note?: string;
}

export interface DetectionRunResult {
  detections: Detection[];
  ruleRuns: RuleRun[];
  durationMs: number;
}

function subjectsFor(rule: RuleDefinition, f: Finding): Detection['subjects'] {
  if (f.subjects) return f.subjects;
  switch (rule.scope) {
    case 'ip':
      return { ips: f.sourceIps, users: [] };
    case 'user':
      return { ips: [], users: f.usernames };
    case 'ip-user':
      return { ips: f.sourceIps.slice(0, 1), users: f.usernames.slice(0, 1) };
    default:
      return { ips: [], users: [] };
  }
}

function categoriesOf(ctx: DetectionContext, ids: number[]): EventCategory[] {
  const set = new Set<EventCategory>();
  for (const id of ids) {
    const e = ctx.events[id];
    if (e) set.add(e.category);
    if (set.size >= 7) break;
  }
  return [...set].sort();
}

function toDetection(
  rule: RuleDefinition,
  f: Finding,
  ctx: DetectionContext,
  used: Set<string>,
): Detection {
  let id = `${rule.id}:${shortHash(`${f.key}|${f.start ?? ''}|${f.eventIds[0] ?? ''}`)}`;
  for (let n = 2; used.has(id); n++)
    id = `${rule.id}:${shortHash(`${f.key}|${f.start ?? ''}|${n}`)}`;
  used.add(id);
  const detection: Detection = {
    id,
    ruleId: rule.id,
    ruleName: rule.name,
    ruleCategory: rule.category,
    severity: f.severity,
    confidence: f.confidence,
    riskScore: scoreFinding(f.severity, f.confidence, f.metric, f.primaryThreshold),
    title: f.title,
    description: rule.description,
    reason: f.reason,
    condition: f.condition,
    thresholds: f.thresholds,
    metric: f.metric,
    metricThreshold: f.primaryThreshold,
    matchedEventCount: f.eventIds.length,
    eventIds: f.eventIds,
    sourceIps: f.sourceIps,
    usernames: f.usernames,
    categories: categoriesOf(ctx, f.eventIds),
    representativeTimestamps: f.representativeTimestamps,
    evidence: f.evidence,
    recommendations: rule.recommendations,
    limitations: [...rule.limitations, ...(f.extraLimitations ?? [])],
    falsePositives: rule.falsePositives,
    mitre: rule.mitre,
    subjects: subjectsFor(rule, f),
  };
  if (f.start !== undefined) detection.start = f.start;
  if (f.end !== undefined) detection.end = f.end;
  if (f.relatedDetectionIds) detection.relatedDetectionIds = f.relatedDetectionIds;
  return detection;
}

function capFindings(findings: Finding[]): { kept: Finding[]; dropped: number } {
  if (findings.length <= MAX_FINDINGS_PER_RULE) return { kept: findings, dropped: 0 };
  const kept = [...findings].sort((a, b) => b.metric - a.metric).slice(0, MAX_FINDINGS_PER_RULE);
  return { kept, dropped: findings.length - kept.length };
}

export function compareDetections(a: Detection, b: Detection): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    b.riskScore - a.riskScore ||
    (a.start ?? Infinity) - (b.start ?? Infinity) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  );
}

/**
 * Run every enabled rule against the dataset. Deterministic: the same events
 * and configuration always produce the same detections, ids and order.
 */
export function runDetections(
  events: readonly NormalizedEvent[],
  configInput: unknown,
  options: { stats?: ParseStats; now?: () => number } = {},
): DetectionRunResult {
  const now = options.now ?? (() => performance.now());
  const started = now();
  const config: DetectionConfig = validateDetectionConfig(configInput);
  const ctx = buildDetectionContext(events, options.stats);
  const detections: Detection[] = [];
  const ruleRuns: RuleRun[] = [];
  const used = new Set<string>();

  const record = (rule: RuleDefinition, run: Omit<RuleRun, 'ruleId' | 'name'>): void => {
    ruleRuns.push({ ruleId: rule.id, name: rule.name, ...run });
  };

  const correlationRules: RuleDefinition[] = [];
  for (const rule of RULES) {
    const rc = config.rules[rule.id];
    if (!rc.enabled) {
      record(rule, {
        enabled: false,
        evaluated: false,
        findings: 0,
        note: 'Disabled in settings.',
      });
      continue;
    }
    if (rule.correlate) {
      correlationRules.push(rule);
      continue;
    }
    const reason = rule.applicable(ctx, rc.params);
    if (reason) {
      record(rule, { enabled: true, evaluated: false, findings: 0, note: reason });
      continue;
    }
    const { kept, dropped } = capFindings(rule.evaluate(ctx, rc.params));
    for (const f of kept) detections.push(toDetection(rule, f, ctx, used));
    record(rule, {
      enabled: true,
      evaluated: true,
      findings: kept.length,
      ...(dropped > 0
        ? {
            note: `${dropped} weaker finding(s) omitted (limit ${MAX_FINDINGS_PER_RULE} per rule).`,
          }
        : {}),
    });
  }

  for (const rule of correlationRules) {
    const rc = config.rules[rule.id];
    const { kept, dropped } = capFindings(rule.correlate!(detections, rc.params));
    const correlated = kept.map((f) => toDetection(rule, f, ctx, used));
    for (const d of correlated) detections.push(d);
    record(rule, {
      enabled: true,
      evaluated: true,
      findings: correlated.length,
      ...(dropped > 0 ? { note: `${dropped} weaker finding(s) omitted.` } : {}),
    });
  }

  detections.sort(compareDetections);
  return { detections, ruleRuns, durationMs: Math.max(0, now() - started) };
}
