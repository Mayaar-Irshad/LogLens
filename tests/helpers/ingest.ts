import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ingestText } from '../../src/features/log-ingestion/ingest';
import { DEFAULT_LIMITS } from '../../src/features/log-ingestion/validation/limits';
import type { LogFormat } from '../../src/types/events';
import type { FieldMapping, IngestResult, ResourceLimits } from '../../src/types/ingestion';

export const TEST_TIMESTAMPS = { assumedYear: 2026, sourceOffsetMinutes: 0 };
/** Fixed reference time so "future timestamp" warnings are deterministic. */
export const TEST_NOW = Date.UTC(2026, 11, 31);

export function fixture(path: string): string {
  return readFileSync(fileURLToPath(new URL(`../fixtures/${path}`, import.meta.url)), 'utf8');
}

export function ingest(
  text: string,
  format: LogFormat,
  extra: {
    mapping?: FieldMapping;
    limits?: Partial<ResourceLimits>;
    sourceOffsetMinutes?: number;
    assumedYear?: number;
  } = {},
): IngestResult {
  return ingestText(text, {
    parse: {
      format,
      timestamps: {
        assumedYear: extra.assumedYear ?? TEST_TIMESTAMPS.assumedYear,
        sourceOffsetMinutes: extra.sourceOffsetMinutes ?? 0,
      },
      ...(extra.mapping ? { mapping: extra.mapping } : {}),
    },
    limits: { ...DEFAULT_LIMITS, ...extra.limits },
    now: TEST_NOW,
  });
}

export const utc = (y: number, mo: number, d: number, h = 0, mi = 0, s = 0, ms = 0): number =>
  Date.UTC(y, mo - 1, d, h, mi, s, ms);
