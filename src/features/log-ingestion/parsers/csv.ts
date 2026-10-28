import type { FieldMapping, TimestampOptions } from '../../../types/ingestion';
import { cleanField } from '../../../utils/text';
import { mapStructuredRecord, type FlatRecord } from '../normalization/structured';
import { WarningCollector, type ParseOutput, type RecordParser } from './types';

export const CSV_DELIMITERS = [',', ';', '\t', '|'] as const;
const MAX_COLUMNS = 200;

/**
 * Advance the quoted-field state across one physical line. As in RFC 4180 and
 * splitCsvRecord, a quote only opens a field at the field's start, so a stray
 * quote inside an unquoted value (27" monitor) does not swallow later lines.
 */
export function scanQuotes(line: string, delimiter: string, inQuotes: boolean): boolean {
  let quoted = inQuotes;
  let fieldStart = !inQuotes;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') i++;
        else quoted = false;
      }
      continue;
    }
    if (ch === '"' && fieldStart) {
      quoted = true;
      fieldStart = false;
      continue;
    }
    fieldStart = ch === delimiter;
  }
  return quoted;
}

/** Pick the delimiter that occurs most often outside quotes in the header row. */
export function detectDelimiter(header: string): string {
  let best: string = ',';
  let bestCount = 0;
  for (const d of CSV_DELIMITERS) {
    let count = 0;
    let inQuotes = false;
    for (const ch of header) {
      if (ch === '"') inQuotes = !inQuotes;
      else if (!inQuotes && ch === d) count++;
    }
    if (count > bestCount) {
      best = d;
      bestCount = count;
    }
  }
  return best;
}

/**
 * Split one complete CSV record (RFC 4180). Quoted fields may contain
 * delimiters, doubled quotes and newlines. Returns null for an unterminated
 * quoted field. Leading "=" or other spreadsheet syntax is plain data here.
 */
export function splitCsvRecord(text: string, delimiter: string): string[] | null {
  const cells: string[] = [];
  let cell = '';
  let i = 0;
  let inQuotes = false;
  let fieldStart = true;
  while (i < text.length) {
    const ch = text[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      cell += ch;
      i++;
      continue;
    }
    if (ch === '"' && fieldStart) {
      inQuotes = true;
      fieldStart = false;
      i++;
      continue;
    }
    if (ch === delimiter) {
      cells.push(cell);
      if (cells.length > MAX_COLUMNS) return cells;
      cell = '';
      fieldStart = true;
      i++;
      continue;
    }
    cell += ch;
    fieldStart = false;
    i++;
  }
  if (inQuotes) return null;
  cells.push(cell);
  return cells;
}

/** Turn header cells into unique, cleaned column names. */
export function normalizeHeader(cells: string[]): string[] {
  const seen = new Map<string, number>();
  return cells.map((cell, i) => {
    const base = cleanField(cell.replace(/^\ufeff/, ''), 128) ?? `column_${i + 1}`;
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    return n === 1 ? base : `${base}_${n}`;
  });
}

export interface CsvParserOptions extends TimestampOptions {
  mapping: FieldMapping;
  delimiter?: string;
  /** Maximum characters in one (possibly multi-line) record. */
  maxRecordLength: number;
  /** Maximum physical lines spanned by one quoted record. */
  maxRecordLines: number;
}

export function createCsvParser(options: CsvParserOptions): RecordParser {
  const warnings = new WarningCollector();
  let delimiter = options.delimiter;
  let header: string[] | null = null;
  let buffer: string[] = [];
  let bufferStart = 0;
  let bufferInQuotes = false;
  let bufferLength = 0;

  const reset = (): void => {
    buffer = [];
    bufferInQuotes = false;
    bufferLength = 0;
  };

  const handleRecord = (text: string, lineNumber: number): ParseOutput => {
    if (header === null) {
      const sep = /^sep=(.)$/i.exec(text.trim());
      if (sep) {
        delimiter = sep[1]!;
        return { type: 'skip', line: lineNumber, reason: 'comment' };
      }
      delimiter ??= detectDelimiter(text);
      const cells = splitCsvRecord(text, delimiter) ?? [];
      header = normalizeHeader(cells.slice(0, MAX_COLUMNS));
      return { type: 'skip', line: lineNumber, reason: 'header' };
    }
    const cells = splitCsvRecord(text, delimiter ?? ',');
    if (cells === null) {
      return {
        type: 'reject',
        line: lineNumber,
        raw: text,
        reason: 'csv_unterminated_quote',
        detail: 'record contains an unterminated quoted field',
      };
    }
    if (cells.every((c) => c.trim() === '')) {
      return {
        type: 'reject',
        line: lineNumber,
        raw: text,
        reason: 'csv_empty_record',
        detail: 'record has no values',
      };
    }
    const record: FlatRecord = new Map();
    const issues: string[] = [];
    cells.forEach((cell, i) => {
      if (cell.trim() === '') return;
      const key = header![i] ?? `column_${i + 1}`;
      record.set(key, cell);
    });
    if (cells.length < header.length) {
      issues.push(`record has ${cells.length} of ${header.length} columns`);
    } else if (cells.length > header.length) {
      issues.push(
        `record has ${cells.length} columns but the header has ${header.length}; extra values kept`,
      );
    }
    const draft = mapStructuredRecord(record, options.mapping, options);
    if (issues.length > 0) draft.issues = [...issues, ...(draft.issues ?? [])];
    return { type: 'event', line: lineNumber, raw: text, drafts: [draft] };
  };

  return {
    format: 'csv',
    push(line, lineNumber) {
      if (buffer.length === 0) bufferStart = lineNumber;
      buffer.push(line);
      bufferInQuotes = scanQuotes(line, delimiter ?? detectDelimiter(line), bufferInQuotes);
      bufferLength += line.length + 1;
      if (bufferInQuotes) {
        if (buffer.length >= options.maxRecordLines || bufferLength > options.maxRecordLength) {
          const raw = buffer.join('\n');
          const start = bufferStart;
          reset();
          return [
            {
              type: 'reject',
              line: start,
              raw,
              reason: 'csv_unterminated_quote',
              detail: `quoted field not closed within ${options.maxRecordLines} lines or ${options.maxRecordLength} characters`,
            },
          ];
        }
        return [];
      }
      const text = buffer.join('\n');
      const start = bufferStart;
      if (buffer.length > 1)
        warnings.add(
          'multiline_records',
          'Some CSV records span multiple lines (quoted newlines).',
        );
      reset();
      return [handleRecord(text, start)];
    },
    isBuffering: () => buffer.length > 0,
    finish() {
      if (buffer.length === 0) return [];
      const raw = buffer.join('\n');
      const start = bufferStart;
      reset();
      return [
        {
          type: 'reject',
          line: start,
          raw,
          reason: 'csv_unterminated_quote',
          detail: 'input ended inside a quoted field',
        },
      ];
    },
    warnings() {
      const list = warnings.list();
      if (!options.mapping.timestamp) {
        list.push({
          code: 'no_timestamp_mapping',
          message:
            'No timestamp column is mapped; time-based charts and windowed detections are unavailable.',
          count: 1,
        });
      }
      return list;
    },
  };
}
