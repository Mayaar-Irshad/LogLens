/**
 * Normalized event model shared by every parser.
 *
 * Common, source-independent attributes (time, source address, account,
 * category, action) live at the top level. Source-specific semantics are kept
 * in typed sections (`auth`, `http`) so that authentication logs and web access
 * logs are not forced into identical assumptions.
 */

export type LogFormat = 'linux-auth' | 'apache' | 'nginx' | 'jsonl' | 'csv';

export const LOG_FORMATS: readonly LogFormat[] = ['linux-auth', 'apache', 'nginx', 'jsonl', 'csv'];

export const LOG_FORMAT_LABELS: Record<LogFormat, string> = {
  'linux-auth': 'Linux auth log (syslog / SSH)',
  apache: 'Apache access log (Common / Combined)',
  nginx: 'Nginx access log (combined)',
  jsonl: 'JSON Lines (newline-delimited JSON)',
  csv: 'CSV with header row',
};

export type EventCategory =
  'authentication' | 'session' | 'privilege' | 'connection' | 'web' | 'system' | 'other';

export const EVENT_CATEGORIES: readonly EventCategory[] = [
  'authentication',
  'session',
  'privilege',
  'connection',
  'web',
  'system',
  'other',
];

export type AuthOutcome = 'success' | 'failure';

/** `parsed`: all expected fields were valid. `partial`: recognized, but some fields were missing or invalid. */
export type ParseStatus = 'parsed' | 'partial';

/** Authentication-specific attributes (sshd, PAM, sudo, su, or mapped structured records). */
export interface AuthDetails {
  /** Outcome of a credential check. Undefined for informational auth messages that are not attempts. */
  outcome?: AuthOutcome;
  /** e.g. password, publickey, keyboard-interactive/pam */
  method?: string;
  /** True when the service reported the account does not exist. */
  invalidUser?: boolean;
  /** Program that produced the record, e.g. sshd, sudo, su. */
  program?: string;
  pid?: number;
  /** Source port of the client connection. */
  port?: number;
  /** For privilege events: the account being switched to (sudo USER=, su to). */
  targetUser?: string;
}

/** HTTP request attributes from web access logs or mapped structured records. */
export interface HttpDetails {
  method?: string;
  /** Request path without the query string, as logged. */
  path?: string;
  query?: string;
  protocol?: string;
  status?: number;
  bytes?: number;
  referrer?: string;
  userAgent?: string;
}

export interface NormalizedEvent {
  /** Sequential identifier within the dataset (0-based). */
  id: number;
  /** 1-based physical line number where the record starts. */
  line: number;
  format: LogFormat;
  category: EventCategory;
  /** Normalized action label, e.g. ssh_login_failed, http_request. */
  action: string;
  /** Epoch milliseconds (UTC). Undefined when the record had no valid timestamp. */
  timestamp?: number;
  /** Timestamp text as it appeared in the source. */
  timestampRaw?: string;
  sourceIp?: string;
  username?: string;
  /** Reporting host (syslog hostname or mapped host field). */
  host?: string;
  /** Free-text message portion, when the source has one. */
  message?: string;
  /** Severity/level reported by the source itself (structured logs only). */
  sourceSeverity?: string;
  auth?: AuthDetails;
  http?: HttpDetails;
  /** Additional safely parsed key/value fields (bounded in count and length). */
  fields?: Array<[string, string]>;
  /** Original record text, exactly as read. Never interpreted as markup or code. */
  raw: string;
  status: ParseStatus;
  /** Human-readable reasons a record is `partial`. */
  issues?: string[];
  /** Present when the event was expanded from a syslog "message repeated N times" line. */
  repeat?: { index: number; of: number };
}

/** An event before the ingestion pipeline assigns identity and bookkeeping fields. */
export type EventDraft = Omit<NormalizedEvent, 'id' | 'line' | 'format' | 'raw' | 'status'> & {
  issues?: string[];
};

export type RejectReason =
  | 'line_too_long'
  | 'unrecognized_format'
  | 'invalid_json'
  | 'not_an_object'
  | 'csv_unterminated_quote'
  | 'csv_empty_record'
  | 'record_too_large';

export type SkipReason = 'blank' | 'comment' | 'header';

export interface RejectedRecord {
  line: number;
  reason: RejectReason;
  detail: string;
  /** Truncated, control-character-escaped preview. Never the full record. */
  preview: string;
  /** Length of the original record in characters. */
  length: number;
}
