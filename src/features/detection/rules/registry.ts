import type { RuleId } from '../../../types/detection';
import type { RuleDefinition } from '../engine/types';
import { AUTH_RULES } from './auth';
import { GENERAL_RULES } from './general';
import { WEB_RULES } from './web';

/** Every detection rule, in evaluation order. Correlation (GEN-003) runs last. */
export const RULES: readonly RuleDefinition[] = [...AUTH_RULES, ...WEB_RULES, ...GENERAL_RULES];

export const RULES_BY_ID: ReadonlyMap<RuleId, RuleDefinition> = new Map(
  RULES.map((r) => [r.id, r]),
);

export function getRule(id: RuleId): RuleDefinition {
  const rule = RULES_BY_ID.get(id);
  if (!rule) throw new Error(`Unknown rule ${id}`);
  return rule;
}

/** Serializable rule metadata for the UI and reports (no functions). */
export interface RuleInfo {
  id: RuleId;
  name: string;
  category: RuleDefinition['category'];
  scope: RuleDefinition['scope'];
  description: string;
  requires: string;
  params: RuleDefinition['params'];
  recommendations: string[];
  limitations: string[];
  falsePositives: string[];
  mitre: RuleDefinition['mitre'];
}

export const RULE_INFO: readonly RuleInfo[] = RULES.map((r) => ({
  id: r.id,
  name: r.name,
  category: r.category,
  scope: r.scope,
  description: r.description,
  requires: r.requires,
  params: r.params,
  recommendations: r.recommendations,
  limitations: r.limitations,
  falsePositives: r.falsePositives,
  mitre: r.mitre,
}));
