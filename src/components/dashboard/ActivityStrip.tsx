import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { useWorkerQuery } from '../../hooks/useWorkerQuery';
import { SEVERITY_RANK, type DetectionSummary, type EntityRisk } from '../../types/detection';
import { formatAxisTime, formatShortTimestamp, formatTimestamp } from '../../utils/format';
import { SeverityBadge } from '../common/Badges';
import { Icon } from '../common/Icon';
import { EmptyState } from '../common/Misc';
import { CHART, SEVERITY_COLORS } from '../charts/chartTheme';
import { Legend } from '../charts/Charts';

const CELLS = 72;
const ROWS = 6;
const CELL_W = 10;
const CELL_H = 18;

/**
 * The overview's signature: for each IP or account that detections are about,
 * its activity across the analyzed period on one shared axis. Cell brightness
 * is the event count, red is the share of failed logins and error responses,
 * and the coloured lines under a row are its detections. Selecting a row
 * filters every view to that indicator.
 */
export function ActivityStrip({
  entities,
  detections,
}: {
  entities: EntityRisk[];
  detections: DetectionSummary[];
}) {
  const { state, actions, client, eventFilter } = useApp();
  const [asTable, setAsTable] = useState(false);
  const rows = entities.slice(0, ROWS);
  const keys = rows.map((e) => ({ kind: e.kind, value: e.value }));
  const key =
    rows.length > 0
      ? `${state.summary?.completedAt}|${state.detectionsVersion}|${JSON.stringify(eventFilter)}|${JSON.stringify(keys)}`
      : null;
  const lanes = useWorkerQuery(key, () =>
    client.query({ type: 'lanes', filter: eventFilter, keys, cells: CELLS }),
  );
  const data = lanes.data;
  const span = data ? data.end - data.start : 0;
  const ticks = data && span > 0 ? [0, 0.25, 0.5, 0.75, 1].map((f) => data.start + f * span) : [];
  const x = (t: number) => (data && span > 0 ? ((t - data.start) / span) * CELLS * CELL_W : 0);

  const selectedFor = (e: EntityRisk) =>
    e.kind === 'ip'
      ? state.filters.sourceIps.includes(e.value)
      : state.filters.usernames.includes(e.value);
  const toggle = (e: EntityRisk) =>
    e.kind === 'ip'
      ? actions.toggleFilter('sourceIps', e.value)
      : actions.toggleFilter('usernames', e.value);
  const detectionsFor = (e: EntityRisk) =>
    detections
      .filter((d) => (e.kind === 'ip' ? d.subjects.ips : d.subjects.users).includes(e.value))
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  return (
    <section className="card" aria-labelledby="strip-title">
      <header className="card-header">
        <div>
          <h2 className="card-title" id="strip-title">
            Indicator activity
          </h2>
          <p className="card-sub">
            The IPs and accounts that detections are about, on one time axis
            {data && span > 0
              ? ` from ${formatShortTimestamp(data.start, state.timeZone)} to ${formatShortTimestamp(data.end, state.timeZone)}`
              : ''}
            .
          </p>
        </div>
        {rows.length > 0 && (
          <div className="card-header-tools">
            {!asTable && (
              <Legend
                items={[
                  { label: 'Events', color: CHART.neutralStrong },
                  { label: 'Failures and errors', color: CHART.risk },
                  { label: 'Detection period', color: SEVERITY_COLORS.high },
                ]}
              />
            )}
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              aria-pressed={asTable}
              onClick={() => setAsTable((v) => !v)}
            >
              <Icon name={asTable ? 'chart' : 'table'} />
              <span>{asTable ? 'Chart' : 'Table'}</span>
            </button>
          </div>
        )}
      </header>

      {rows.length === 0 ? (
        <EmptyState title="No IP or account is the subject of a detection with the current filters." />
      ) : lanes.error ? (
        <p className="text-danger">Activity could not be loaded: {lanes.error}</p>
      ) : !data ? (
        <p className="muted">Loading activity…</p>
      ) : asTable ? (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Indicator activity</caption>
            <thead>
              <tr>
                <th scope="col">Indicator</th>
                <th scope="col" className="num">
                  Events
                </th>
                <th scope="col" className="num">
                  Failures and errors
                </th>
                <th scope="col">First seen</th>
                <th scope="col">Last seen</th>
                <th scope="col">Detections</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => {
                const lane = data.lanes[i];
                return (
                  <tr key={`${e.kind}:${e.value}`}>
                    <td className="mono">{e.value}</td>
                    <td className="num">{lane?.total.toLocaleString('en-US') ?? '—'}</td>
                    <td className="num">{lane?.risky.toLocaleString('en-US') ?? '—'}</td>
                    <td>
                      {lane?.first !== undefined
                        ? formatTimestamp(lane.first, state.timeZone)
                        : '—'}
                    </td>
                    <td>
                      {lane?.last !== undefined ? formatTimestamp(lane.last, state.timeZone) : '—'}
                    </td>
                    <td className="small">{e.ruleIds.join(' ')}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="strip">
          {rows.map((e, i) => {
            const lane = data.lanes[i];
            if (!lane) return null;
            const max = Math.max(1, ...lane.cells.map((c) => c.total));
            const spans = detectionsFor(e);
            return (
              <button
                key={`${e.kind}:${e.value}`}
                type="button"
                className={`strip-row${selectedFor(e) ? ' selected' : ''}`}
                aria-pressed={selectedFor(e)}
                aria-label={`${e.kind === 'ip' ? 'Source IP' : 'Account'} ${e.value}: ${lane.total} events, ${lane.risky} failures or errors, ${spans.length} detections. Select to filter every view.`}
                onClick={() => toggle(e)}
              >
                <span className="strip-label">
                  <span className="strip-name">
                    <SeverityBadge severity={e.maxSeverity} />
                    <span className="mono">{e.value}</span>
                  </span>
                  <span className="strip-meta">
                    {lane.total.toLocaleString('en-US')} events ·{' '}
                    {lane.risky.toLocaleString('en-US')} failed
                  </span>
                </span>
                <svg
                  viewBox={`0 0 ${CELLS * CELL_W} 30`}
                  preserveAspectRatio="none"
                  aria-hidden="true"
                >
                  {lane.cells.map((c, j) => {
                    if (c.total === 0) {
                      return (
                        <rect
                          key={j}
                          x={j * CELL_W + 1}
                          y={CELL_H / 2}
                          width={CELL_W - 2}
                          height={1}
                          fill={CHART.grid}
                        />
                      );
                    }
                    const strength = 0.25 + 0.75 * Math.sqrt(c.total / max);
                    const riskH = (c.risky / c.total) * CELL_H;
                    return (
                      <g key={j}>
                        <rect
                          x={j * CELL_W + 1}
                          y={0}
                          width={CELL_W - 2}
                          height={CELL_H}
                          fill={CHART.neutralStrong}
                          fillOpacity={strength * 0.55}
                        />
                        {riskH > 0 && (
                          <rect
                            x={j * CELL_W + 1}
                            y={CELL_H - riskH}
                            width={CELL_W - 2}
                            height={riskH}
                            fill={CHART.risk}
                            fillOpacity={strength}
                          />
                        )}
                      </g>
                    );
                  })}
                  {spans.map((d, k) =>
                    d.start !== undefined && d.end !== undefined ? (
                      <line
                        key={d.id}
                        x1={x(d.start)}
                        x2={Math.max(x(d.end), x(d.start) + 3)}
                        y1={23 + (k % 3) * 2.5}
                        y2={23 + (k % 3) * 2.5}
                        stroke={SEVERITY_COLORS[d.severity]}
                        strokeWidth={2}
                        vectorEffect="non-scaling-stroke"
                      />
                    ) : null,
                  )}
                </svg>
              </button>
            );
          })}
          <div className="strip-axis" aria-hidden="true">
            <span />
            <span className="strip-ticks">
              {ticks.map((t, i) => (
                <span key={i} style={{ left: `${(i / (ticks.length - 1)) * 100}%` }}>
                  {formatAxisTime(t, state.timeZone, span)}
                </span>
              ))}
            </span>
          </div>
        </div>
      )}
    </section>
  );
}
