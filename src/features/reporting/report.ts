import type { DashboardFilters, DashboardMetrics, DisplayTimeZone } from '../../types/analytics';
import type {
  AlertStatus,
  DetectionConfig,
  DetectionSummary,
  EntityRisk,
} from '../../types/detection';
import type { NormalizedEvent } from '../../types/events';
import type { AnalysisSummary } from '../../workers/protocol';
import type { RuleRun } from '../detection/engine/runDetections';
import type { Posture } from '../detection/risk/risk';
import { formatOffset } from '../../utils/format';
import { escapeInvisible } from '../../utils/text';

export const APP_NAME = 'LogLens';
export const REPORT_SCHEMA = 'loglens.report/v1';
/** Supporting events referenced per detection in a report. */
export const REPORT_EVENTS_PER_DETECTION = 20;

export interface ReportOptions {
  /** Include analyst notes and statuses. */
  includeNotes: boolean;
  /** Include original log lines for referenced events. Off by default. */
  includeRawEvidence: boolean;
}

export interface ReportInput {
  appVersion: string;
  generatedAt: number;
  timeZone: DisplayTimeZone;
  summary: AnalysisSummary;
  detections: DetectionSummary[];
  ruleRuns: RuleRun[];
  entities: EntityRisk[];
  posture: Posture;
  metrics: DashboardMetrics;
  detectionConfig: DetectionConfig;
  /** Present when the report covers a filtered view rather than the full dataset. */
  filters: DashboardFilters | null;
  statuses: Readonly<Record<string, AlertStatus>>;
  notes: Readonly<Record<string, string>>;
  caseNote: string;
  /** Supporting events by detection id (already limited by the caller). */
  evidence: ReadonlyMap<string, NormalizedEvent[]>;
  options: ReportOptions;
}

const iso = (ms: number | undefined): string | null =>
  ms === undefined ? null : new Date(ms).toISOString();

function eventReference(e: NormalizedEvent, includeRaw: boolean) {
  return {
    eventId: e.id,
    line: e.line,
    timestamp: iso(e.timestamp),
    category: e.category,
    action: e.action,
    sourceIp: e.sourceIp ?? null,
    username: e.username ?? null,
    ...(e.auth?.outcome ? { authOutcome: e.auth.outcome } : {}),
    ...(e.http
      ? {
          http: {
            method: e.http.method ?? null,
            path: e.http.path ?? null,
            status: e.http.status ?? null,
          },
        }
      : {}),
    ...(includeRaw ? { rawLogLine: escapeInvisible(e.raw) } : {}),
  };
}

function compactFilters(filters: DashboardFilters): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(filters)) {
    if (
      Array.isArray(value)
        ? value.length > 0
        : typeof value === 'string'
          ? value !== ''
          : value !== undefined
    ) {
      if (key === 'timeRange') {
        const range = value as DashboardFilters['timeRange'];
        if (range.start !== undefined || range.end !== undefined)
          out.timeRange = { start: iso(range.start), end: iso(range.end) };
      } else out[key] = value;
    }
  }
  return out;
}

/** Build the JSON investigation report. Pure: everything it needs is passed in. */
export function buildReport(input: ReportInput) {
  const { summary, options } = input;
  const stats = summary.stats;
  const ts = summary.parseOptions.timestamps;
  const limitations = [
    'Findings come from deterministic, threshold-based rules applied to the uploaded data only. They are leads for investigation, not confirmed incidents or attribution.',
    'No external threat intelligence, IP reputation, geolocation or machine learning was used.',
    `Only parsed records were analyzed: ${stats.rejectedRecords} record(s) were rejected and ${stats.partialRecords} partially parsed.`,
    `Timestamps without zone information were interpreted as ${formatOffset(ts.sourceOffsetMinutes)}.${summary.format === 'linux-auth' ? ` Syslog timestamps have no year; ${ts.assumedYear} was assumed.` : ''}`,
    'Address classifications (private, public, documentation) describe address space, not intent.',
    ...(summary.limitReached
      ? ['The event limit was reached; later lines were counted but not analyzed.']
      : []),
    ...(stats.eventsWithoutTimestamp > 0
      ? [
          `${stats.eventsWithoutTimestamp} event(s) had no valid timestamp and were excluded from time-window rules.`,
        ]
      : []),
  ];

  return {
    schema: REPORT_SCHEMA,
    application: { name: APP_NAME, version: input.appVersion },
    generatedAt: iso(input.generatedAt),
    scan: {
      completedAt: iso(summary.completedAt),
      source: {
        name: escapeInvisible(summary.source.name),
        kind: summary.source.kind,
        sizeBytes: summary.source.sizeBytes,
      },
      format: summary.format,
      parseOptions: summary.parseOptions,
      limits: summary.limits,
      parsing: {
        ...stats,
        warnings: stats.warnings.map((w) => ({ code: w.code, message: w.message, count: w.count })),
      },
      timing: summary.timing,
    },
    displayTimeZone: input.timeZone === 'UTC' ? 'UTC' : 'browser local time',
    analysisTimeRange: {
      start: iso(input.metrics.timeRange.start),
      end: iso(input.metrics.timeRange.end),
    },
    scope: input.filters
      ? { type: 'filtered', filters: compactFilters(input.filters) }
      : { type: 'full-dataset' },
    metrics: {
      totalEvents: input.metrics.totalEvents,
      timedEvents: input.metrics.timedEvents,
      uniqueSourceIps: input.metrics.uniqueIps,
      uniqueUsernames: input.metrics.uniqueUsers,
      categories: input.metrics.categories,
      authentication: input.metrics.auth,
      web: input.metrics.web,
      topSourceIps: input.metrics.topIps,
      topUsernames: input.metrics.topUsers,
      flaggedEvents: input.metrics.flaggedEvents,
    },
    posture: {
      level: input.posture.level,
      summary: input.posture.summary,
      severityCounts: input.posture.counts,
    },
    detectionConfig: input.detectionConfig,
    ruleRuns: input.ruleRuns,
    detections: input.detections.map((d) => {
      const evidence = (input.evidence.get(d.id) ?? []).slice(0, REPORT_EVENTS_PER_DETECTION);
      return {
        id: d.id,
        ruleId: d.ruleId,
        ruleName: d.ruleName,
        severity: d.severity,
        confidence: d.confidence,
        riskScore: d.riskScore,
        title: d.title,
        description: d.description,
        reason: d.reason,
        condition: d.condition,
        thresholds: d.thresholds,
        measured: { value: d.metric, threshold: d.metricThreshold },
        matchedEventCount: d.matchedEventCount,
        start: iso(d.start),
        end: iso(d.end),
        representativeTimestamps: d.representativeTimestamps.map((t) => iso(t)),
        sourceIps: d.sourceIps,
        usernames: d.usernames,
        evidenceSummary: d.evidence,
        eventReferences: evidence.map((e) => eventReference(e, options.includeRawEvidence)),
        eventReferencesTruncated: d.matchedEventCount > evidence.length,
        recommendations: d.recommendations,
        limitations: d.limitations,
        falsePositiveConsiderations: d.falsePositives,
        mitreAttack: d.mitre,
        ...(d.relatedDetectionIds ? { relatedDetectionIds: d.relatedDetectionIds } : {}),
        ...(options.includeNotes
          ? { analystStatus: input.statuses[d.id] ?? 'open', analystNote: input.notes[d.id] ?? '' }
          : {}),
      };
    }),
    riskyIndicators: input.entities.slice(0, 25),
    ...(options.includeNotes ? { investigationNote: input.caseNote } : {}),
    limitations,
    privacy: {
      generatedLocally: true,
      rawLogLinesIncluded: options.includeRawEvidence,
      analystNotesIncluded: options.includeNotes,
    },
  };
}

export type LogLensReport = ReturnType<typeof buildReport>;

/**
 * Serialize as JSON. HTML-significant characters and line separators are
 * escaped as \u sequences (still valid JSON) so the file is inert if it is
 * ever embedded in a web page.
 */
export function serializeReport(report: unknown): string {
  return JSON.stringify(report, null, 2)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}
