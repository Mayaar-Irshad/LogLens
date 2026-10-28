import type {
  Confidence,
  Detection,
  EvidenceItem,
  MitreReference,
  RuleCategory,
  RuleId,
  RuleParamSpec,
  Severity,
  Threshold,
} from '../../../types/detection';
import type { NormalizedEvent } from '../../../types/events';
import type { ParseStats } from '../../../types/ingestion';

/** Whose behaviour a rule describes; used by correlation and entity risk. */
export type RuleScope = 'ip' | 'user' | 'ip-user' | 'global' | 'dataset';

/** Raw output of a rule before the engine assigns identity and risk. */
export interface Finding {
  /** Entity or group key, used for the deterministic detection id. */
  key: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  reason: string;
  condition: string;
  thresholds: Threshold[];
  /** The measured value compared against the primary threshold. */
  metric: number;
  /** The primary threshold value the metric was compared with. */
  primaryThreshold: number;
  eventIds: number[];
  sourceIps: string[];
  usernames: string[];
  start?: number;
  end?: number;
  representativeTimestamps: number[];
  evidence: EvidenceItem[];
  extraLimitations?: string[];
  relatedDetectionIds?: string[];
  /** Entities the finding is about, when they differ from sourceIps/usernames (e.g. AUTH-004). */
  subjects?: { ips: string[]; users: string[] };
}

export interface DetectionContext {
  events: readonly NormalizedEvent[];
  /** Authentication events with a known outcome and timestamp, sorted by time. */
  authAttempts: NormalizedEvent[];
  /** Subset of authAttempts with outcome = failure. */
  authFailures: NormalizedEvent[];
  /** Events with HTTP details, sorted by time where timestamps exist. */
  webRequests: NormalizedEvent[];
  /** Web requests that have timestamps, sorted. */
  timedWebRequests: NormalizedEvent[];
  /** All timestamped events, sorted. */
  timedEvents: NormalizedEvent[];
  /** Counts of relevant events that were excluded because they lack timestamps. */
  untimed: { auth: number; web: number; all: number };
  stats?: ParseStats;
}

export interface RuleDefinition {
  id: RuleId;
  name: string;
  category: RuleCategory;
  scope: RuleScope;
  description: string;
  /** What data the rule needs, in plain language. */
  requires: string;
  params: RuleParamSpec[];
  recommendations: string[];
  limitations: string[];
  falsePositives: string[];
  mitre: MitreReference[];
  /** Returns a reason when the dataset cannot support this rule, or null. */
  applicable(ctx: DetectionContext, params: Record<string, number>): string | null;
  evaluate(ctx: DetectionContext, params: Record<string, number>): Finding[];
  /** Correlation rules run after all other rules, over their detections. */
  correlate?(detections: Detection[], params: Record<string, number>): Finding[];
}
