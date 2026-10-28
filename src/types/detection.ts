import type { EventCategory } from './events';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Strength of the evidence behind a detection — not the probability of compromise. */
export type Confidence = 'low' | 'medium' | 'high';

export type RuleCategory = 'authentication' | 'web' | 'general';

export type RuleId =
  | 'AUTH-001'
  | 'AUTH-002'
  | 'AUTH-003'
  | 'AUTH-004'
  | 'AUTH-005'
  | 'AUTH-006'
  | 'AUTH-007'
  | 'WEB-001'
  | 'WEB-002'
  | 'WEB-003'
  | 'WEB-004'
  | 'WEB-005'
  | 'WEB-006'
  | 'WEB-007'
  | 'WEB-008'
  | 'WEB-009'
  | 'GEN-001'
  | 'GEN-002'
  | 'GEN-003';

export interface RuleParamSpec {
  key: string;
  label: string;
  description: string;
  min: number;
  max: number;
  step: number;
  integer: boolean;
  unit?: string;
  default: number;
}

export interface RuleConfig {
  enabled: boolean;
  params: Record<string, number>;
}

export interface DetectionConfig {
  rules: Record<RuleId, RuleConfig>;
}

export interface Threshold {
  name: string;
  value: number | string;
  unit?: string;
}

export interface EvidenceItem {
  label: string;
  value: string;
}

export interface MitreReference {
  id: string;
  name: string;
}

export interface Detection {
  /** Deterministic identifier: stable across re-runs with identical input and configuration. */
  id: string;
  ruleId: RuleId;
  ruleName: string;
  ruleCategory: RuleCategory;
  severity: Severity;
  confidence: Confidence;
  /** 0–100, see features/detection/risk. */
  riskScore: number;
  title: string;
  description: string;
  /** Plain-language explanation of exactly why the rule fired. */
  reason: string;
  /** The rule condition with configured values substituted. */
  condition: string;
  thresholds: Threshold[];
  /** The measured value (e.g. peak failures in a window) compared with `metricThreshold`. */
  metric: number;
  metricThreshold: number;
  matchedEventCount: number;
  /** Supporting event ids (complete inside the worker; sampled when sent to the UI). */
  eventIds: number[];
  sourceIps: string[];
  usernames: string[];
  /** Categories of the supporting events. */
  categories: EventCategory[];
  start?: number;
  end?: number;
  /** First, peak, and last timestamps of interest, where known. */
  representativeTimestamps: number[];
  evidence: EvidenceItem[];
  recommendations: string[];
  limitations: string[];
  falsePositives: string[];
  mitre: MitreReference[];
  /** For correlation detections: the detections that contributed. */
  relatedDetectionIds?: string[];
  /** The IPs and accounts the detection is about (used for correlation and entity risk). */
  subjects: { ips: string[]; users: string[] };
}

/** A detection as sent to the UI: eventIds is a bounded sample. */
export interface DetectionSummary extends Detection {
  eventIdsSampled: boolean;
}

export type AlertStatus = 'open' | 'reviewed' | 'unresolved';

export const ALERT_STATUSES: readonly AlertStatus[] = ['open', 'reviewed', 'unresolved'];

export interface EntityRisk {
  kind: 'ip' | 'user';
  value: string;
  score: number;
  maxSeverity: Severity;
  ruleIds: RuleId[];
  detectionIds: string[];
  eventCount: number;
}
