import { useMemo, useState } from 'react';
import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import { clearFilters, statusOf } from '../../features/investigation/filters';
import { RULE_INFO } from '../../features/detection/rules/registry';
import { ALERT_STATUSES, SEVERITIES, type RuleId } from '../../types/detection';
import { buildAlertTimeline, byPriority } from '../../features/investigation/detections';
import { AlertTimelineChart } from '../charts/Charts';
import { SeverityBadge, StatusBadge } from '../common/Badges';
import { Callout, EmptyState, PageHeader, Time } from '../common/Misc';
import { AlertDetail } from './AlertDetail';

type SortKey = 'priority' | 'time' | 'events';

export function AlertsView() {
  const { state, actions } = useApp();
  const { detections, error } = useData();
  const [sort, setSort] = useState<SortKey>('priority');
  const f = state.filters;

  const sorted = useMemo(() => {
    const list = [...detections];
    if (sort === 'priority') list.sort(byPriority);
    else if (sort === 'time') list.sort((a, b) => (a.start ?? Infinity) - (b.start ?? Infinity));
    else list.sort((a, b) => b.matchedEventCount - a.matchedEventCount);
    return list;
  }, [detections, sort]);

  // A detection opened from elsewhere (an event, a correlation) may be hidden by the current
  // filters. Show it anyway, with a notice, rather than silently opening a different one.
  const requested = state.selectedDetectionId
    ? state.detections.find((d) => d.id === state.selectedDetectionId)
    : undefined;
  const hidden = requested !== undefined && !sorted.some((d) => d.id === requested.id);
  const selected = hidden
    ? requested
    : (sorted.find((d) => d.id === state.selectedDetectionId) ?? sorted[0]);
  const timeline = useMemo(
    () => buildAlertTimeline(detections, state.timeZone),
    [detections, state.timeZone],
  );
  const triggeredRules = RULE_INFO.filter((r) => state.detections.some((d) => d.ruleId === r.id));

  return (
    <div className="view">
      <PageHeader
        title="Detections"
        description={`${detections.length} of ${state.detections.length} detections match the current filters. Each explains why it fired, shows its evidence and suggests next steps; review status and notes last for this session only.`}
      />
      {error && (
        <Callout tone="danger" title="Detections could not be scoped to the current filters.">
          {error}
        </Callout>
      )}
      <AlertTimelineChart
        points={timeline.points}
        bucketMs={timeline.bucketMs}
        timeZone={state.timeZone}
        onSelectBucket={(start, end) => actions.setFilters({ ...f, timeRange: { start, end } })}
      />
      <section className="card alert-filters" aria-label="Detection filters">
        <fieldset className={`toggle-group${f.severities.length ? ' has-selection' : ''}`}>
          <legend>Severity</legend>
          {SEVERITIES.map((s) => (
            <label key={s} className={`toggle${f.severities.includes(s) ? ' on' : ''}`}>
              <input
                type="checkbox"
                checked={f.severities.includes(s)}
                onChange={() => actions.toggleFilter('severities', s)}
              />
              <SeverityBadge severity={s} />
            </label>
          ))}
        </fieldset>
        <fieldset className={`toggle-group${f.alertStatuses.length ? ' has-selection' : ''}`}>
          <legend>Status</legend>
          {ALERT_STATUSES.map((s) => (
            <label key={s} className={`toggle${f.alertStatuses.includes(s) ? ' on' : ''}`}>
              <input
                type="checkbox"
                checked={f.alertStatuses.includes(s)}
                onChange={() => actions.toggleFilter('alertStatuses', s)}
              />
              <StatusBadge status={s} />
            </label>
          ))}
        </fieldset>
        <div className="field">
          <label className="field-label" htmlFor="rule-filter">
            Rule
          </label>
          <select
            id="rule-filter"
            className="select"
            value={f.ruleIds.length === 1 ? f.ruleIds[0] : ''}
            onChange={(e) =>
              actions.setFilters({
                ...f,
                ruleIds: e.target.value ? [e.target.value as RuleId] : [],
              })
            }
          >
            <option value="">All triggered rules</option>
            {triggeredRules.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} — {r.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="alert-sort">
            Sort by
          </label>
          <select
            id="alert-sort"
            className="select"
            value={sort}
            onChange={(e) => setSort(e.target.value as SortKey)}
          >
            <option value="priority">Severity and risk</option>
            <option value="time">First seen</option>
            <option value="events">Matching events</option>
          </select>
        </div>
      </section>

      {sorted.length === 0 && !hidden ? (
        <EmptyState title="No detections match the current data, filters and thresholds.">
          {state.detections.length === 0
            ? 'No rule triggered for this dataset. That is not proof that nothing happened: check the rule thresholds and which rules could be evaluated on the Detection rules page.'
            : 'Clear or change filters to see other detections.'}
        </EmptyState>
      ) : (
        <div className="split">
          <section className="card alert-list-card" aria-label="Detections">
            <p className="muted small">
              {sorted.length} detection{sorted.length === 1 ? '' : 's'}
            </p>
            {sorted.length === 0 && <p className="muted">None match the current filters.</p>}
            <ul className="alert-list">
              {sorted.map((d) => (
                <li key={d.id}>
                  <button
                    type="button"
                    className={`alert-item${selected?.id === d.id ? ' selected' : ''}`}
                    aria-current={selected?.id === d.id ? 'true' : undefined}
                    onClick={() => actions.dispatch({ type: 'selectDetection', id: d.id })}
                  >
                    <span className="alert-item-top">
                      <SeverityBadge severity={d.severity} />
                      {statusOf(state.statuses, d.id) !== 'open' && (
                        <StatusBadge status={statusOf(state.statuses, d.id)} />
                      )}
                    </span>
                    <span className="alert-item-title">{d.title}</span>
                    <span className="alert-item-meta">
                      {d.ruleId} · {d.matchedEventCount.toLocaleString('en-US')} events ·{' '}
                      <Time ms={d.start} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
          <div className="grid">
            {hidden && (
              <Callout tone="warn" title="This detection is hidden by the current filters.">
                <button
                  type="button"
                  className="link-button"
                  onClick={() => actions.setFilters(clearFilters())}
                >
                  Clear filters
                </button>{' '}
                to see it in the list.
              </Callout>
            )}
            {selected && <AlertDetail key={selected.id} detection={selected} />}
          </div>
        </div>
      )}
    </div>
  );
}
