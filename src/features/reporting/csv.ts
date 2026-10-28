import type { DisplayTimeZone } from '../../types/analytics';
import type { NormalizedEvent } from '../../types/events';
import { formatTimestamp } from '../../utils/format';
import { escapeInvisible } from '../../utils/text';
import type { DetectionIndex } from '../analytics/detectionIndex';

/** Characters that make spreadsheet applications interpret a cell as a formula. */
const FORMULA_TRIGGERS = /^[=+\-@\t\r\uff1d\uff0b\uff0d\uff20]/;

/**
 * Encode one CSV cell. Every cell is quoted and inner quotes doubled
 * (RFC 4180). Cells that a spreadsheet would treat as a formula are prefixed
 * with an apostrophe (OWASP CSV-injection guidance), so "=HYPERLINK(...)"
 * from a log is shown as text instead of being executed.
 */
export function csvCell(value: string | number | boolean | undefined | null): string {
  if (value === undefined || value === null) return '""';
  let text = String(value);
  if (FORMULA_TRIGGERS.test(text.trimStart()) && typeof value !== 'number') text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function csvRow(values: Array<string | number | boolean | undefined | null>): string {
  return values.map(csvCell).join(',');
}

export const EVENT_CSV_COLUMNS = [
  'event_id',
  'line',
  'timestamp',
  'format',
  'category',
  'action',
  'source_ip',
  'username',
  'host',
  'auth_outcome',
  'http_method',
  'http_path',
  'http_status',
  'user_agent',
  'parse_status',
  'parse_issues',
  'max_detection_severity',
  'detection_ids',
] as const;

export const MAX_EXPORT_ROWS = 200_000;

export interface CsvExportResult {
  csv: string;
  rows: number;
  truncated: boolean;
  includesRaw: boolean;
}

/**
 * Export events as CSV. The original log line is excluded unless the analyst
 * explicitly asks for it. Output is capped at MAX_EXPORT_ROWS rows.
 */
export function eventsToCsv(
  events: readonly NormalizedEvent[],
  ids: readonly number[],
  options: { includeRaw: boolean; timeZone: DisplayTimeZone; index?: DetectionIndex },
): CsvExportResult {
  const header = [...EVENT_CSV_COLUMNS, ...(options.includeRaw ? ['raw_log_line'] : [])];
  const lines = [csvRow(header)];
  const limit = Math.min(ids.length, MAX_EXPORT_ROWS);
  for (let i = 0; i < limit; i++) {
    const e = events[ids[i]!]!;
    const row: Array<string | number | undefined> = [
      e.id,
      e.line,
      e.timestamp === undefined ? '' : formatTimestamp(e.timestamp, options.timeZone),
      e.format,
      e.category,
      e.action,
      e.sourceIp,
      e.username,
      e.host,
      e.auth?.outcome,
      e.http?.method,
      e.http?.path,
      e.http?.status,
      e.http?.userAgent,
      e.status,
      (e.issues ?? []).join('; '),
      options.index?.maxSeverity(e.id),
      (options.index?.detectionIdsFor(e.id) ?? []).join(' '),
    ];
    if (options.includeRaw) row.push(escapeInvisible(e.raw));
    lines.push(csvRow(row));
  }
  return {
    csv: `${lines.join('\r\n')}\r\n`,
    rows: limit,
    truncated: ids.length > limit,
    includesRaw: options.includeRaw,
  };
}
