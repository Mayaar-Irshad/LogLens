export interface NumberSpec {
  min: number;
  max: number;
  integer: boolean;
  default: number;
}

/**
 * Coerce an untrusted value to a finite number within [min, max]. Non-numeric
 * input falls back to the default. Used for every configuration value that
 * crosses a trust boundary (form input, worker messages).
 */
export function clampNumber(value: unknown, spec: NumberSpec): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isFinite(n)) return spec.default;
  const bounded = Math.min(spec.max, Math.max(spec.min, n));
  return spec.integer ? Math.round(bounded) : bounded;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
