import type { ReactNode } from 'react';
import { useApp } from '../../app/AppContext';
import { statusOf } from '../../features/investigation/filters';
import { byPriority } from '../../features/investigation/detections';
import type { DetectionSummary, EntityRisk, RuleId } from '../../types/detection';
import { SeverityBadge, StatusBadge } from '../common/Badges';
import { EmptyState, IpLabel, Time } from '../common/Misc';

export interface KpiItem {
  label: string;
  value: ReactNode;
  unit?: string;
  sub?: ReactNode;
  /** The figure that answers the screen's question is set larger. */
  lead?: boolean;
  tone?: 'neg' | 'warn';
}

/** KPIs as type in one container split by dividers, not as separate tiles. */
export function KpiStrip({ items, label }: { items: KpiItem[]; label: string }) {
  return (
    <section className="kpi-strip" aria-label={label}>
      {items.map((k) => (
        <div key={k.label} className={`kpi${k.lead ? ' kpi-lead' : ''}`}>
          <div className="kpi-label">{k.label}</div>
          <div className={`kpi-value${k.tone ? ` ${k.tone}` : ''}`}>
            {k.value}
            {k.unit && <span className="kpi-unit">{k.unit}</span>}
          </div>
          {k.sub !== undefined && <div className="kpi-sub">{k.sub}</div>}
        </div>
      ))}
    </section>
  );
}

/** Compact detection list; selecting an item opens it in the Detections view. */
export function DetectionList({
  detections,
  limit = 6,
  emptyText,
}: {
  detections: DetectionSummary[];
  limit?: number;
  emptyText: string;
}) {
  const { state, actions } = useApp();
  const shown = [...detections].sort(byPriority).slice(0, limit);
  if (shown.length === 0) return <EmptyState title={emptyText} />;
  return (
    <>
      <ul className="mini-list">
        {shown.map((d) => {
          const status = statusOf(state.statuses, d.id);
          return (
            <li key={d.id}>
              <button
                type="button"
                className="mini-item"
                onClick={() => {
                  actions.dispatch({ type: 'selectDetection', id: d.id });
                  actions.navigate('alerts');
                }}
              >
                <SeverityBadge severity={d.severity} />
                <span className="mini-main">
                  <span className="mini-title">{d.title}</span>
                  <span className="mini-sub">
                    {d.ruleId} · <Time ms={d.start} />
                  </span>
                </span>
                {status !== 'open' && <StatusBadge status={status} />}
                <span className="mini-count num" title="Supporting events">
                  {d.matchedEventCount.toLocaleString('en-US')}
                  <span className="muted small"> ev</span>
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      {detections.length > limit && (
        <button
          type="button"
          className="link-button small mini-more"
          onClick={() => actions.navigate('alerts')}
        >
          View all {detections.length} detections
        </button>
      )}
    </>
  );
}

export function DetectionGroup({
  title,
  description,
  ruleIds,
  detections,
}: {
  title: string;
  description: string;
  ruleIds: RuleId[];
  detections: DetectionSummary[];
}) {
  const matching = detections.filter((d) => ruleIds.includes(d.ruleId));
  return (
    <section className="card" aria-label={title}>
      <header className="card-header">
        <div>
          <h2 className="card-title">
            {title} <span className="count">{matching.length}</span>
          </h2>
          <p className="card-sub">{description}</p>
        </div>
      </header>
      <DetectionList
        detections={matching}
        limit={4}
        emptyText={`No ${title.toLowerCase()} detections with the current filters and thresholds.`}
      />
    </section>
  );
}

/** Detections per rule, most frequent first; each row filters every view by that rule. */
export function RulesTriggered({ detections }: { detections: DetectionSummary[] }) {
  const { state, actions } = useApp();
  const counts = new Map<RuleId, { name: string; count: number }>();
  for (const d of detections) {
    const entry = counts.get(d.ruleId) ?? { name: d.ruleName, count: 0 };
    entry.count++;
    counts.set(d.ruleId, entry);
  }
  const rows = [...counts]
    .sort((a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : 1))
    .slice(0, 5);
  if (rows.length === 0) return null;
  return (
    <div className="rules-triggered">
      <h3 className="section-title">Rules triggered</h3>
      <ul className="donut-legend">
        {rows.map(([id, r]) => (
          <li key={id} className={state.filters.ruleIds.includes(id) ? 'selected' : undefined}>
            <button
              type="button"
              aria-pressed={state.filters.ruleIds.includes(id)}
              onClick={() => actions.toggleFilter('ruleIds', id)}
              title={r.name}
            >
              <span className="mono">{id}</span>
              <span className="rule-name">{r.name}</span>
              <span className="legend-value">{r.count}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RiskyIndicators({ entities }: { entities: EntityRisk[] }) {
  const { actions } = useApp();
  if (entities.length === 0) {
    return <EmptyState title="No IP or account is the subject of a detection." />;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Indicator</th>
            <th scope="col">Rules</th>
            <th scope="col" className="num">
              Score
            </th>
          </tr>
        </thead>
        <tbody>
          {entities.slice(0, 5).map((e) => (
            <tr key={`${e.kind}:${e.value}`}>
              <td>
                <button
                  type="button"
                  className="link-button"
                  title={`Filter every view to this ${e.kind === 'ip' ? 'IP' : 'account'}`}
                  onClick={() =>
                    actions.pivot(
                      e.kind === 'ip' ? { sourceIps: [e.value] } : { usernames: [e.value] },
                      'overview',
                    )
                  }
                >
                  {e.kind === 'ip' ? (
                    <IpLabel ip={e.value} />
                  ) : (
                    <span className="mono">{e.value}</span>
                  )}
                </button>
                <div className="muted small">{e.kind === 'ip' ? 'Source IP' : 'Account'}</div>
              </td>
              <td className="small muted">{e.ruleIds.join(' ')}</td>
              <td className="num">
                <span title={`Highest severity: ${e.maxSeverity}`}>{e.score}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
