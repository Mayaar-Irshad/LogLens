import type { ParseOptions, ResourceLimits } from '../../types/ingestion';
import { createAccessLogParser } from './parsers/accessLog';
import { createCsvParser } from './parsers/csv';
import { createJsonlParser } from './parsers/jsonl';
import { createLinuxAuthParser } from './parsers/linuxAuth';
import type { RecordParser } from './parsers/types';

export function createParser(options: ParseOptions, limits: ResourceLimits): RecordParser {
  const ts = options.timestamps;
  switch (options.format) {
    case 'linux-auth':
      return createLinuxAuthParser({ ...ts, maxRepeatExpansion: limits.maxRepeatExpansion });
    case 'apache':
    case 'nginx':
      return createAccessLogParser(options.format, ts);
    case 'jsonl':
      return createJsonlParser({ ...ts, mapping: options.mapping ?? {} });
    case 'csv':
      return createCsvParser({
        ...ts,
        mapping: options.mapping ?? {},
        ...(options.csvDelimiter ? { delimiter: options.csvDelimiter } : {}),
        maxRecordLength: limits.maxLineLength * 4,
        maxRecordLines: 50,
      });
  }
}
