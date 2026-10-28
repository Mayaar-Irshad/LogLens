import type { LogFormat, NormalizedEvent, RejectedRecord } from './events';

/** Resource safeguards applied to every scan. */
export interface ResourceLimits {
  /** Maximum input size in bytes. */
  maxFileSizeBytes: number;
  /** Physical lines longer than this many characters are rejected without parsing. */
  maxLineLength: number;
  /** Maximum number of events kept. Further lines are counted but not analyzed. */
  maxEvents: number;
  /** Upper bound for expanding syslog "message repeated N times" lines. */
  maxRepeatExpansion: number;
  /** Number of rejected-record samples retained for inspection. */
  maxRejectedSamples: number;
  /** Seconds before an analysis run is aborted. */
  analysisTimeoutSeconds: number;
}

export type MappableField =
  | 'timestamp'
  | 'eventType'
  | 'action'
  | 'outcome'
  | 'sourceIp'
  | 'username'
  | 'host'
  | 'httpMethod'
  | 'path'
  | 'statusCode'
  | 'userAgent'
  | 'message'
  | 'severity';

export const MAPPABLE_FIELDS: readonly MappableField[] = [
  'timestamp',
  'eventType',
  'action',
  'outcome',
  'sourceIp',
  'username',
  'host',
  'httpMethod',
  'path',
  'statusCode',
  'userAgent',
  'message',
  'severity',
];

export const MAPPABLE_FIELD_LABELS: Record<MappableField, string> = {
  timestamp: 'Timestamp',
  eventType: 'Event type',
  action: 'Action',
  outcome: 'Outcome (success / failure)',
  sourceIp: 'Source IP',
  username: 'Username',
  host: 'Host',
  httpMethod: 'HTTP method',
  path: 'URL path',
  statusCode: 'HTTP status code',
  userAgent: 'User agent',
  message: 'Message',
  severity: 'Source severity / level',
};

/** Maps a normalized field to a source key (CSV header or dotted JSON path). */
export type FieldMapping = Partial<Record<MappableField, string>>;

export interface TimestampOptions {
  /** Year applied to syslog timestamps, which do not include one. */
  assumedYear: number;
  /** Offset (minutes east of UTC) applied to timestamps that carry no zone. */
  sourceOffsetMinutes: number;
}

export interface ParseOptions {
  format: LogFormat;
  timestamps: TimestampOptions;
  mapping?: FieldMapping;
  /** CSV delimiter; detected from the header row when omitted. */
  csvDelimiter?: string;
}

export interface ParseWarning {
  code: string;
  message: string;
  count: number;
}

export interface ParseStats {
  /** Physical lines read from the input. */
  totalLines: number;
  blankLines: number;
  /** Comment and header lines intentionally skipped. */
  skippedLines: number;
  /** Records where every expected field was valid. */
  parsedRecords: number;
  /** Records recognized but with missing or invalid fields. */
  partialRecords: number;
  rejectedRecords: number;
  /** Events created (can exceed records when repeated messages are expanded). */
  eventsCreated: number;
  /** Extra events created from "message repeated N times" lines. */
  expandedRepeats: number;
  /** Non-blank lines identical to an earlier line. They are kept, not dropped. */
  duplicateLines: number;
  /** Lines read after the event limit was reached; counted but not analyzed. */
  unprocessedLines: number;
  eventsWithoutTimestamp: number;
  bytesRead: number;
  warnings: ParseWarning[];
}

export interface IngestResult {
  format: LogFormat;
  events: NormalizedEvent[];
  rejected: RejectedRecord[];
  stats: ParseStats;
  limitReached: boolean;
}

export interface FormatCandidate {
  format: LogFormat;
  /** Fraction of sampled lines that matched (0–1). */
  score: number;
}

export interface FormatDetection {
  format: LogFormat | null;
  confidence: number;
  ambiguous: boolean;
  candidates: FormatCandidate[];
  reason: string;
  /** Present when the sample looks like binary or compressed content. */
  unsupportedReason?: string;
}

/** Keys discovered in structured (CSV/JSONL) samples, used by the field-mapping UI. */
export interface StructuredSample {
  /** Keys in first-seen order with up to a few example values (truncated, escaped). */
  keys: Array<{ key: string; examples: string[] }>;
  suggestedMapping: FieldMapping;
  delimiter?: string;
}
