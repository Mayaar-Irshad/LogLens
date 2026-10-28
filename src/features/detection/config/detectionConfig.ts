import type { DetectionConfig, RuleConfig, RuleId } from '../../../types/detection';
import { clampNumber, isRecord } from '../../../utils/validation';
import { RULES } from '../rules/registry';

export function defaultRuleConfig(ruleId: RuleId): RuleConfig {
  const rule = RULES.find((r) => r.id === ruleId);
  return {
    enabled: true,
    params: Object.fromEntries((rule?.params ?? []).map((p) => [p.key, p.default])),
  };
}

export function defaultDetectionConfig(): DetectionConfig {
  return {
    rules: Object.fromEntries(
      RULES.map((r) => [r.id, defaultRuleConfig(r.id)]),
    ) as DetectionConfig['rules'],
  };
}

/**
 * Validate an untrusted detection configuration (from the settings form or a
 * worker message). Unknown rules and parameters are dropped, missing values
 * fall back to defaults, and every number is clamped to its documented range.
 */
export function validateDetectionConfig(input: unknown): DetectionConfig {
  const rulesIn = isRecord(input) && isRecord(input.rules) ? input.rules : {};
  const rules = {} as DetectionConfig['rules'];
  for (const rule of RULES) {
    const raw = Object.prototype.hasOwnProperty.call(rulesIn, rule.id)
      ? rulesIn[rule.id]
      : undefined;
    const source = isRecord(raw) ? raw : {};
    const paramsIn = isRecord(source.params) ? source.params : {};
    const params: Record<string, number> = {};
    for (const spec of rule.params) {
      const value = Object.prototype.hasOwnProperty.call(paramsIn, spec.key)
        ? paramsIn[spec.key]
        : undefined;
      params[spec.key] = clampNumber(value, spec);
    }
    rules[rule.id] = {
      enabled: typeof source.enabled === 'boolean' ? source.enabled : true,
      params,
    };
  }
  return { rules };
}
