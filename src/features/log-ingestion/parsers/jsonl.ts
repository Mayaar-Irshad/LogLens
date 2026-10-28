import type { FieldMapping, TimestampOptions } from '../../../types/ingestion';
import { flattenObject, mapStructuredRecord, type FlatRecord } from '../normalization/structured';
import type { ParseOutput, RecordParser } from './types';

export type JsonParseResult =
  | { ok: true; record: FlatRecord }
  | { ok: false; reason: 'invalid_json' | 'not_an_object'; detail: string };

/**
 * Parse one JSON Lines record. JSON.parse never executes code; the result is
 * flattened into a Map so untrusted keys cannot affect object prototypes.
 * Error details intentionally do not echo the record content.
 */
export function parseJsonRecord(line: string): JsonParseResult {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return {
      ok: false,
      reason: 'invalid_json',
      detail: 'line is not valid JSON (possibly truncated)',
    };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return {
      ok: false,
      reason: 'not_an_object',
      detail: `expected a JSON object, found ${Array.isArray(value) ? 'an array' : value === null ? 'null' : typeof value}`,
    };
  }
  return { ok: true, record: flattenObject(value as Record<string, unknown>) };
}

export function createJsonlParser(
  options: TimestampOptions & { mapping: FieldMapping },
): RecordParser {
  const parseLine = (line: string, lineNumber: number): ParseOutput => {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#')) {
      return { type: 'skip', line: lineNumber, reason: 'comment' };
    }
    const parsed = parseJsonRecord(trimmed);
    if (!parsed.ok) {
      return {
        type: 'reject',
        line: lineNumber,
        raw: line,
        reason: parsed.reason,
        detail: parsed.detail,
      };
    }
    return {
      type: 'event',
      line: lineNumber,
      raw: line,
      drafts: [mapStructuredRecord(parsed.record, options.mapping, options)],
    };
  };

  return {
    format: 'jsonl',
    push: (line, lineNumber) => [parseLine(line, lineNumber)],
    finish: () => [],
    isBuffering: () => false,
    warnings: () =>
      options.mapping.timestamp
        ? []
        : [
            {
              code: 'no_timestamp_mapping',
              message:
                'No timestamp field is mapped; time-based charts and windowed detections are unavailable.',
              count: 1,
            },
          ],
  };
}
