import { LOG_FORMATS, type LogFormat } from '../../../types/events';
import { MAPPABLE_FIELDS, type FieldMapping, type ParseOptions } from '../../../types/ingestion';
import { clampNumber, isRecord } from '../../../utils/validation';
import { CSV_DELIMITERS } from '../parsers/csv';
import { MAX_YEAR, MIN_YEAR } from '../normalization/timestamp';

/** Validate untrusted parse options (from the UI or a worker message). */
export function validateParseOptions(input: unknown): ParseOptions {
  const src = isRecord(input) ? input : {};
  const format: LogFormat = LOG_FORMATS.includes(src.format as LogFormat)
    ? (src.format as LogFormat)
    : 'linux-auth';
  const ts = isRecord(src.timestamps) ? src.timestamps : {};
  const options: ParseOptions = {
    format,
    timestamps: {
      assumedYear: clampNumber(ts.assumedYear, {
        min: MIN_YEAR,
        max: MAX_YEAR,
        integer: true,
        default: new Date().getUTCFullYear(),
      }),
      sourceOffsetMinutes: clampNumber(ts.sourceOffsetMinutes, {
        min: -14 * 60,
        max: 14 * 60,
        integer: true,
        default: 0,
      }),
    },
  };
  if (isRecord(src.mapping)) {
    const mapping: FieldMapping = {};
    for (const field of MAPPABLE_FIELDS) {
      const value = Object.prototype.hasOwnProperty.call(src.mapping, field)
        ? src.mapping[field]
        : undefined;
      if (typeof value === 'string' && value.length > 0 && value.length <= 256)
        mapping[field] = value;
    }
    options.mapping = mapping;
  }
  if (
    typeof src.csvDelimiter === 'string' &&
    (CSV_DELIMITERS as readonly string[]).includes(src.csvDelimiter)
  ) {
    options.csvDelimiter = src.csvDelimiter;
  }
  return options;
}
