import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import {
  defaultDetectionConfig,
  validateDetectionConfig,
} from '../../features/detection/config/detectionConfig';
import { RULE_INFO, type RuleInfo } from '../../features/detection/rules/registry';
import { LIMIT_SPECS, MB, validateLimits } from '../../features/log-ingestion/validation/limits';
import type { DetectionConfig, RuleCategory } from '../../types/detection';
import type { ResourceLimits } from '../../types/ingestion';
import { Callout, PageHeader } from '../common/Misc';

const GROUPS: Array<{ category: RuleCategory; title: string }> = [
  { category: 'authentication', title: 'Authentication rules' },
  { category: 'web', title: 'Web server rules' },
  { category: 'general', title: 'General rules' },
];

function RuleRow({
  rule,
  config,
  onChange,
}: {
  rule: RuleInfo;
  config: DetectionConfig;
  onChange: (c: DetectionConfig) => void;
}) {
  const { state } = useApp();
  const rc = config.rules[rule.id];
  const run = state.ruleRuns.find((r) => r.ruleId === rule.id);
  const setParam = (key: string, raw: string) => {
    onChange({
      ...config,
      rules: {
        ...config.rules,
        [rule.id]: { ...rc, params: { ...rc.params, [key]: Number(raw) } },
      },
    });
  };
  return (
    <article
      className={`rule-row${rc.enabled ? '' : ' disabled'}`}
      aria-labelledby={`rule-${rule.id}`}
    >
      <header className="rule-head">
        <label className="switch">
          <input
            type="checkbox"
            checked={rc.enabled}
            onChange={(e) =>
              onChange({
                ...config,
                rules: { ...config.rules, [rule.id]: { ...rc, enabled: e.target.checked } },
              })
            }
          />
          <span className="visually-hidden">Enable {rule.name}</span>
        </label>
        <div>
          <h3 id={`rule-${rule.id}`} className="rule-title">
            <span className="mono">{rule.id}</span> {rule.name}
          </h3>
          <p className="rule-desc">{rule.description}</p>
          <p className="muted small">Requires: {rule.requires}</p>
          {run && (
            <p className={`rule-run small${run.evaluated && run.findings > 0 ? '' : ' muted'}`}>
              Last run:{' '}
              {!run.enabled
                ? 'disabled'
                : run.evaluated
                  ? `${run.findings} finding${run.findings === 1 ? '' : 's'}`
                  : `not evaluated — ${run.note ?? ''}`}
              {run.evaluated && run.note ? ` (${run.note})` : ''}
            </p>
          )}
        </div>
      </header>
      {rule.params.length > 0 && (
        <div className="param-grid">
          {rule.params.map((p) => {
            const value = rc.params[p.key] ?? p.default;
            const invalid =
              !Number.isFinite(value) ||
              value < p.min ||
              value > p.max ||
              (p.integer && !Number.isInteger(value));
            const id = `${rule.id}-${p.key}`;
            return (
              <div className="field" key={p.key}>
                <label className="field-label" htmlFor={id}>
                  {p.label} {p.unit && <span className="muted">({p.unit})</span>}
                </label>
                <input
                  id={id}
                  className="input"
                  type="number"
                  inputMode="numeric"
                  min={p.min}
                  max={p.max}
                  step={p.step}
                  value={Number.isFinite(value) ? value : ''}
                  aria-invalid={invalid}
                  aria-describedby={`${id}-hint`}
                  disabled={!rc.enabled}
                  onChange={(e) => setParam(p.key, e.target.value)}
                />
                <span id={`${id}-hint`} className={`field-hint${invalid ? ' text-danger' : ''}`}>
                  {invalid ? `Must be between ${p.min} and ${p.max}. ` : ''}
                  {p.description} Default {p.default}.
                </span>
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}

export function RulesView() {
  const { state, actions } = useApp();
  const [draft, setDraft] = useState<DetectionConfig>(state.detectionConfig);
  const [applied, setApplied] = useState<DetectionConfig>(state.detectionConfig);
  const [limits, setLimits] = useState<ResourceLimits>(state.limits);
  if (applied !== state.detectionConfig) {
    setApplied(state.detectionConfig);
    setDraft(state.detectionConfig);
  }

  const dirty =
    JSON.stringify(validateDetectionConfig(draft)) !== JSON.stringify(state.detectionConfig);
  const hasInvalid = RULE_INFO.some((r) =>
    r.params.some((p) => {
      const v = draft.rules[r.id].params[p.key];
      return v === undefined || !Number.isFinite(v) || v < p.min || v > p.max;
    }),
  );
  const ready = state.scan.phase === 'ready';

  return (
    <div className="view">
      <PageHeader
        title="Detection rules"
        description="Transparent, deterministic threshold rules. Every value is validated and clamped to its documented range before use. Settings are kept in memory for this session."
        actions={
          <>
            <button
              type="button"
              className="btn"
              onClick={() => setDraft(defaultDetectionConfig())}
            >
              Reset to defaults
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!dirty || hasInvalid || state.redetecting}
              onClick={() => void actions.applyDetectionConfig(draft)}
            >
              {state.redetecting ? 'Re-running…' : ready ? 'Apply and re-run detections' : 'Apply'}
            </button>
          </>
        }
      />
      {hasInvalid && (
        <Callout tone="warn">
          Some values are outside their allowed range. Fix them before applying.
        </Callout>
      )}
      {!ready && (
        <Callout tone="info">No dataset is loaded. Settings apply to the next scan.</Callout>
      )}
      {state.redetectError && (
        <Callout tone="danger" title="Detections were not re-run.">
          {state.redetectError} The previous settings and detections are still in effect.{' '}
          <button
            type="button"
            className="link-button"
            onClick={() => void actions.applyDetectionConfig(draft)}
          >
            Try again
          </button>
        </Callout>
      )}
      {state.lastRedetect && !state.redetectError && !state.redetecting && (
        <Callout tone="success" title="Detections re-run.">
          {state.lastRedetect.before} → {state.lastRedetect.after} detections (
          {state.lastRedetect.added} new, {state.lastRedetect.removed} no longer triggered). Review
          status is kept for detections that still exist.
        </Callout>
      )}

      {GROUPS.map((g) => (
        <section key={g.category} className="card" aria-labelledby={`group-${g.category}`}>
          <header className="card-header">
            <h2 className="card-title" id={`group-${g.category}`}>
              {g.title}{' '}
              <span className="count">
                {RULE_INFO.filter((r) => r.category === g.category).length}
              </span>
            </h2>
          </header>
          <div className="rule-list">
            {RULE_INFO.filter((r) => r.category === g.category).map((r) => (
              <RuleRow key={r.id} rule={r} config={draft} onChange={setDraft} />
            ))}
          </div>
        </section>
      ))}

      <section className="card" aria-labelledby="limits-title">
        <header className="card-header">
          <div>
            <h2 className="card-title" id="limits-title">
              Resource limits
            </h2>
            <p className="card-sub">
              Safeguards against oversized or malformed input. Applied to the next scan. Larger
              limits use more browser memory.
            </p>
          </div>
        </header>
        <div className="param-grid">
          {(Object.keys(LIMIT_SPECS) as Array<keyof ResourceLimits>).map((key) => {
            const spec = LIMIT_SPECS[key];
            const isBytes = key === 'maxFileSizeBytes';
            const shown = isBytes ? Math.round(limits[key] / MB) : limits[key];
            return (
              <div className="field" key={key}>
                <label className="field-label" htmlFor={`limit-${key}`}>
                  {spec.label} <span className="muted">({isBytes ? 'MB' : spec.unit})</span>
                </label>
                <input
                  id={`limit-${key}`}
                  className="input"
                  type="number"
                  min={isBytes ? spec.min / MB : spec.min}
                  max={isBytes ? spec.max / MB : spec.max}
                  value={shown}
                  onChange={(e) =>
                    setLimits({
                      ...limits,
                      [key]: isBytes ? Number(e.target.value) * MB : Number(e.target.value),
                    })
                  }
                />
                <span className="field-hint">
                  Range{' '}
                  {isBytes
                    ? `${spec.min / MB}–${spec.max / MB}`
                    : `${spec.min.toLocaleString('en-US')}–${spec.max.toLocaleString('en-US')}`}
                  , default {isBytes ? spec.default / MB : spec.default.toLocaleString('en-US')}.
                </span>
              </div>
            );
          })}
        </div>
        <div className="form-actions">
          <button
            type="button"
            className="btn"
            onClick={() => {
              const valid = validateLimits(limits);
              setLimits(valid);
              actions.dispatch({ type: 'setLimits', limits: valid });
            }}
          >
            Save limits
          </button>
        </div>
      </section>
    </div>
  );
}
