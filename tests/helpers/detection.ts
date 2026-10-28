import { defaultDetectionConfig } from '../../src/features/detection/config/detectionConfig';
import { runDetections } from '../../src/features/detection/engine/runDetections';
import type { RuleId } from '../../src/types/detection';
import type { NormalizedEvent } from '../../src/types/events';

/** Run a single rule (all others disabled) with optional parameter overrides. */
export function runOnly(
  ruleId: RuleId,
  events: NormalizedEvent[],
  params: Record<string, number> = {},
) {
  const config = defaultDetectionConfig();
  for (const id of Object.keys(config.rules) as RuleId[]) config.rules[id].enabled = id === ruleId;
  Object.assign(config.rules[ruleId].params, params);
  return runDetections(events, config);
}
