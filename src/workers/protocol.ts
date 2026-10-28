import type {
  DashboardMetrics,
  DisplayTimeZone,
  EventFilter,
  EventPage,
  EventRow,
  EventSort,
  RelatedBy,
} from '../types/analytics';
import type { DetectionConfig, DetectionSummary, EntityRisk } from '../types/detection';
import type { LogFormat, RejectedRecord } from '../types/events';
import type { ParseOptions, ParseStats, ResourceLimits } from '../types/ingestion';
import type { RuleRun } from '../features/detection/engine/runDetections';
import type { Posture } from '../features/detection/risk/risk';
import type { RelatedResult } from '../features/analytics/query';
import type { LaneKey, LanesResult } from '../features/analytics/lanes';
import type { CsvExportResult } from '../features/reporting/csv';
import type { SampleId } from '../features/sample-data/samples';

/** Message protocol between the UI thread and the analysis worker. */

export type AnalyzeSource =
  | { kind: 'file'; file: Blob; name: string }
  | { kind: 'text'; text: string; name: string }
  | { kind: 'sample'; sampleId: SampleId };

export interface AnalyzeOptions {
  parse: ParseOptions;
  limits: ResourceLimits;
  detection: DetectionConfig;
  timeZone: DisplayTimeZone;
}

export type ScanPhase = 'reading' | 'detecting' | 'indexing' | 'done';

export interface ScanProgress {
  phase: ScanPhase;
  bytesProcessed: number;
  totalBytes: number;
  linesProcessed: number;
  eventsCreated: number;
}

export interface Capabilities {
  hasAuth: boolean;
  hasWeb: boolean;
  hasTimestamps: boolean;
  hasIps: boolean;
  hasUsers: boolean;
}

export interface AnalysisSummary {
  source: { name: string; kind: AnalyzeSource['kind']; sizeBytes: number };
  format: LogFormat;
  parseOptions: ParseOptions;
  limits: ResourceLimits;
  stats: ParseStats;
  rejected: RejectedRecord[];
  limitReached: boolean;
  detections: DetectionSummary[];
  ruleRuns: RuleRun[];
  entities: EntityRisk[];
  posture: Posture;
  metrics: DashboardMetrics;
  capabilities: Capabilities;
  timing: { parseMs: number; detectMs: number; totalMs: number };
  completedAt: number;
}

export interface RedetectResult {
  detections: DetectionSummary[];
  ruleRuns: RuleRun[];
  entities: EntityRisk[];
  posture: Posture;
  metrics: DashboardMetrics;
  durationMs: number;
}

export interface MetricsResult {
  metrics: DashboardMetrics;
  /** Detection ids with at least one supporting event in the filtered set; null = no event filter. */
  detectionIdsInScope: string[] | null;
  matchingEvents: number;
}

export type WorkerRequest =
  | { id: number; type: 'analyze'; source: AnalyzeSource; options: AnalyzeOptions }
  | { id: number; type: 'redetect'; detection: DetectionConfig; timeZone: DisplayTimeZone }
  | { id: number; type: 'metrics'; filter: EventFilter }
  | {
      id: number;
      type: 'events';
      filter: EventFilter;
      sort: EventSort;
      page: number;
      pageSize: number;
    }
  | { id: number; type: 'eventsById'; ids: number[] }
  | { id: number; type: 'detectionEvents'; detectionId: string; page: number; pageSize: number }
  | {
      id: number;
      type: 'related';
      eventId: number;
      by: RelatedBy;
      windowMinutes: number;
      limit: number;
    }
  | {
      id: number;
      type: 'exportEvents';
      filter: EventFilter;
      includeRaw: boolean;
      timeZone: DisplayTimeZone;
    }
  | { id: number; type: 'lanes'; filter: EventFilter; keys: LaneKey[]; cells: number }
  | { id: number; type: 'reset' };

export type WorkerRequestType = WorkerRequest['type'];

export interface ResultMap {
  analyze: AnalysisSummary;
  redetect: RedetectResult;
  metrics: MetricsResult;
  events: EventPage;
  eventsById: EventRow[];
  detectionEvents: EventPage;
  related: RelatedResult;
  exportEvents: CsvExportResult;
  lanes: LanesResult;
  reset: { ok: true };
}

export type WorkerResponse =
  | { id: number; type: 'progress'; progress: ScanProgress }
  | { id: number; type: 'result'; result: ResultMap[WorkerRequestType] }
  | { id: number; type: 'error'; error: { message: string; code: WorkerErrorCode } };

export type WorkerErrorCode = 'no_dataset' | 'invalid_request' | 'input_too_large' | 'internal';

/** Number of supporting event ids sent with each detection summary. */
export const DETECTION_SAMPLE_IDS = 200;
