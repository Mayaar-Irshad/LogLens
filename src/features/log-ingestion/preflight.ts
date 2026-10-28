import type { FormatDetection, StructuredSample } from '../../types/ingestion';
import { previewText } from '../../utils/text';
import { detectFormat } from './detectFormat';
import { suggestMapping, type FieldValue, type FlatRecord } from './normalization/structured';
import { detectDelimiter, normalizeHeader, splitCsvRecord } from './parsers/csv';
import { parseJsonRecord } from './parsers/jsonl';

/** Bytes read from the start of a file to detect its format and fields. */
export const PREFLIGHT_SAMPLE_BYTES = 64 * 1024;
const MAX_KEYS = 100;
const MAX_EXAMPLES = 3;

export interface Preflight {
  detection: FormatDetection;
  jsonl?: StructuredSample;
  csv?: StructuredSample;
  sampleLineCount: number;
}

/** Split sample text into lines, dropping a trailing partial line when the sample was cut. */
export function sampleLines(text: string, truncated: boolean): string[] {
  const lines = text.replace(/^\ufeff/, '').split(/\r\n|\r|\n/);
  if (truncated && lines.length > 1) lines.pop();
  return lines;
}

function buildSample(records: FlatRecord[], delimiter?: string): StructuredSample {
  const order: string[] = [];
  const values = new Map<string, FieldValue[]>();
  for (const record of records) {
    for (const [key, value] of record) {
      let list = values.get(key);
      if (!list) {
        if (order.length >= MAX_KEYS) continue;
        list = [];
        values.set(key, list);
        order.push(key);
      }
      list.push(value);
    }
  }
  const keys = order.map((key) => {
    const distinct = [...new Set((values.get(key) ?? []).map((v) => String(v)))].slice(
      0,
      MAX_EXAMPLES,
    );
    return { key, examples: distinct.map((v) => previewText(v, 60)) };
  });
  return {
    keys,
    suggestedMapping: suggestMapping(order, (key) => values.get(key) ?? []),
    ...(delimiter ? { delimiter } : {}),
  };
}

export function sampleJsonl(lines: string[]): StructuredSample | undefined {
  const records: FlatRecord[] = [];
  for (const line of lines) {
    if (records.length >= 200) break;
    if (line.trim() === '') continue;
    const parsed = parseJsonRecord(line.trim());
    if (parsed.ok) records.push(parsed.record);
  }
  return records.length > 0 ? buildSample(records) : undefined;
}

export function sampleCsv(lines: string[]): StructuredSample | undefined {
  const nonBlank = lines.filter((l) => l.trim() !== '');
  let start = 0;
  let delimiter: string | undefined;
  const sep = /^sep=(.)$/i.exec(nonBlank[0]?.trim() ?? '');
  if (sep) {
    delimiter = sep[1];
    start = 1;
  }
  const headerLine = nonBlank[start];
  if (headerLine === undefined) return undefined;
  delimiter ??= detectDelimiter(headerLine);
  const header = normalizeHeader(splitCsvRecord(headerLine, delimiter) ?? []);
  if (header.length < 2) return undefined;
  const records: FlatRecord[] = [];
  for (const line of nonBlank.slice(start + 1, start + 201)) {
    const cells = splitCsvRecord(line, delimiter);
    if (!cells) continue;
    const record: FlatRecord = new Map();
    cells.forEach((c, i) => {
      if (c.trim() !== '' && header[i] !== undefined) record.set(header[i], c);
    });
    records.push(record);
  }
  // Ensure every header column is listed even when the sample rows leave it empty.
  const headerRecord: FlatRecord = new Map();
  const sample = buildSample(records, delimiter);
  const known = new Set(sample.keys.map((k) => k.key));
  for (const h of header) if (!known.has(h)) headerRecord.set(h, '');
  for (const key of headerRecord.keys()) sample.keys.push({ key, examples: [] });
  return sample;
}

/** Run format detection and field discovery on the first part of an input. */
export function runPreflight(
  text: string,
  options: { fileName?: string; truncated: boolean },
): Preflight {
  const lines = sampleLines(text, options.truncated);
  const detection = detectFormat(lines, options.fileName ?? '');
  const result: Preflight = {
    detection,
    sampleLineCount: lines.filter((l) => l.trim() !== '').length,
  };
  if (detection.unsupportedReason) return result;
  const jsonl = sampleJsonl(lines);
  if (jsonl) result.jsonl = jsonl;
  const csv = sampleCsv(lines);
  if (csv) result.csv = csv;
  return result;
}
