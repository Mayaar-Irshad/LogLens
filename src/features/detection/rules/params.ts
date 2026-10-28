import type { RuleParamSpec } from '../../../types/detection';

/** Parameter spec helpers so every rule describes its knobs the same way. */
export const windowParam = (defaultMinutes: number, max = 1440): RuleParamSpec => ({
  key: 'windowMinutes',
  label: 'Time window',
  description: 'Events must fall within this many minutes of each other to be counted together.',
  min: 1,
  max,
  step: 1,
  integer: true,
  unit: 'min',
  default: defaultMinutes,
});

export const countParam = (
  key: string,
  label: string,
  description: string,
  defaultValue: number,
  min = 1,
  max = 100_000,
  unit = 'events',
): RuleParamSpec => ({
  key,
  label,
  description,
  min,
  max,
  step: 1,
  integer: true,
  unit,
  default: defaultValue,
});

export const SEVERITY_ESCALATION_NOTE =
  'Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.';
