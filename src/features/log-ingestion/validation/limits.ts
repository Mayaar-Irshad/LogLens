import type { ResourceLimits } from '../../../types/ingestion';
import { clampNumber, isRecord, type NumberSpec } from '../../../utils/validation';

export const MB = 1024 * 1024;

export const LIMIT_SPECS: Record<
  keyof ResourceLimits,
  NumberSpec & { label: string; unit: string }
> = {
  maxFileSizeBytes: {
    label: 'Maximum input size',
    unit: 'bytes',
    min: 1 * MB,
    max: 200 * MB,
    integer: true,
    default: 25 * MB,
  },
  maxLineLength: {
    label: 'Maximum line length',
    unit: 'characters',
    min: 1024,
    max: 262_144,
    integer: true,
    default: 16_384,
  },
  maxEvents: {
    label: 'Maximum events analyzed',
    unit: 'events',
    min: 1_000,
    max: 2_000_000,
    integer: true,
    default: 500_000,
  },
  maxRepeatExpansion: {
    label: 'Maximum expansion of "message repeated N times"',
    unit: 'events per line',
    min: 1,
    max: 10_000,
    integer: true,
    default: 1_000,
  },
  maxRejectedSamples: {
    label: 'Rejected records kept for inspection',
    unit: 'records',
    min: 10,
    max: 5_000,
    integer: true,
    default: 500,
  },
  analysisTimeoutSeconds: {
    label: 'Analysis timeout',
    unit: 'seconds',
    min: 10,
    max: 900,
    integer: true,
    default: 120,
  },
};

export const DEFAULT_LIMITS: ResourceLimits = {
  maxFileSizeBytes: LIMIT_SPECS.maxFileSizeBytes.default,
  maxLineLength: LIMIT_SPECS.maxLineLength.default,
  maxEvents: LIMIT_SPECS.maxEvents.default,
  maxRepeatExpansion: LIMIT_SPECS.maxRepeatExpansion.default,
  maxRejectedSamples: LIMIT_SPECS.maxRejectedSamples.default,
  analysisTimeoutSeconds: LIMIT_SPECS.analysisTimeoutSeconds.default,
};

/** Validate untrusted limit settings, clamping each value into its allowed range. */
export function validateLimits(input: unknown): ResourceLimits {
  const source = isRecord(input) ? input : {};
  const out = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(LIMIT_SPECS) as Array<keyof ResourceLimits>) {
    out[key] = clampNumber(source[key], LIMIT_SPECS[key]);
  }
  return out;
}
