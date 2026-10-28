import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { statusOf } from '../../features/investigation/filters';
import { useWorkerQuery } from '../../hooks/useWorkerQuery';
import { ALERT_STATUSES, type DetectionSummary } from '../../types/detection';
import { ConfidenceBadge, RiskScore, SeverityBadge } from '../common/Badges';
import { Icon } from '../common/Icon';
import { IpLabel, Pagination, Time } from '../common/Misc';
import { EventTable } from '../events/EventTable';

const EVIDENCE_PAGE = 10;
const PIVOT_PADDING_MS = 15 * 60_000;

export function AlertDetail({ detection }: { detection: DetectionSummary }) {
  const { state, actions, client } = useApp();
  // The parent renders this component with key={detection.id}, so paging resets per detection.
  const [page, setPage] = useState(0);
  const evidence = useWorkerQuery(
    `${state.summary?.completedAt}|${state.detectionsVersion}|${detection.id}|${page}`,
    () =>
      client.query({
        type: 'detectionEvents',
        detectionId: detection.id,
        page,
        pageSize: EVIDENCE_PAGE,
      }),
  );
  const status = statusOf(state.statuses, detection.id);
  const note = state.notes[detection.id] ?? '';
  const related = detection.relatedDetectionIds
    ? state.detections.filter((d) => detection.relatedDetectionIds!.includes(d.id))
    : [];
  const window =
    detection.start !== undefined && detection.end !== undefined
      ? { start: detection.start - PIVOT_PADDING_MS, end: detection.end + PIVOT_PADDING_MS }
      : null;

  return (
    <article className="card detail-panel" aria-labelledby="alert-title">
      <header className="alert-head">
        <div className="alert-badges">
          <SeverityBadge severity={detection.severity} />
          <ConfidenceBadge confidence={detection.confidence} />
          <RiskScore score={detection.riskScore} />
        </div>
        <h2 id="alert-title" className="alert-title">
          {detection.title}
        </h2>
        <p className="muted small">
          <span className="mono">{detection.ruleId}</span> · {detection.ruleName} ·{' '}
          <span className="mono">{detection.id}</span>
        </p>
        <div className="segmented" role="radiogroup" aria-label="Review status (this session only)">
          {ALERT_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              role="radio"
              aria-checked={status === s}
              className={status === s ? 'active' : ''}
              onClick={() => actions.dispatch({ type: 'setStatus', id: detection.id, status: s })}
            >
              {s === 'open' ? 'Open' : s === 'reviewed' ? 'Reviewed' : 'Unresolved'}
            </button>
          ))}
        </div>
      </header>

      <section className="detail-section">
        <h3 className="section-title">Why this was flagged</h3>
        <p>{detection.reason}</p>
        <p className="muted small">
          <strong>Condition:</strong> {detection.condition}
        </p>
        <div className="table-wrap">
          <table className="table compact">
            <caption className="visually-hidden">Thresholds</caption>
            <thead>
              <tr>
                <th scope="col">Threshold</th>
                <th scope="col" className="num">
                  Configured
                </th>
              </tr>
            </thead>
            <tbody>
              {detection.thresholds.map((t) => (
                <tr key={t.name}>
                  <td>{t.name}</td>
                  <td className="num">
                    {String(t.value)} {t.unit ?? ''}
                  </td>
                </tr>
              ))}
              <tr>
                <td>
                  <strong>Measured value</strong>
                </td>
                <td className="num">
                  <strong>{detection.metric.toLocaleString('en-US')}</strong> vs{' '}
                  {detection.metricThreshold.toLocaleString('en-US')}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="detail-section">
        <h3 className="section-title">Evidence</h3>
        <dl className="kv">
          <div className="kv-row">
            <dt>Matching events</dt>
            <dd>{detection.matchedEventCount.toLocaleString('en-US')}</dd>
          </div>
          <div className="kv-row">
            <dt>First seen</dt>
            <dd>
              <Time ms={detection.start} />
            </dd>
          </div>
          <div className="kv-row">
            <dt>Last seen</dt>
            <dd>
              <Time ms={detection.end} />
            </dd>
          </div>
          {detection.representativeTimestamps.length > 2 && (
            <div className="kv-row">
              <dt>Peak window ended</dt>
              <dd>
                <Time ms={detection.representativeTimestamps[1]} />
              </dd>
            </div>
          )}
          {detection.evidence.map((e) => (
            <div className="kv-row" key={e.label}>
              <dt>{e.label}</dt>
              <dd className="break">{e.value}</dd>
            </div>
          ))}
        </dl>
        {(detection.sourceIps.length > 0 || detection.usernames.length > 0) && (
          <div className="entities">
            {detection.sourceIps.slice(0, 12).map((ip) => (
              <button
                key={`ip-${ip}`}
                type="button"
                className="entity"
                onClick={() => actions.pivot({ sourceIps: [ip] })}
                title="Show all events from this IP"
              >
                <Icon name="filter" size={12} /> <IpLabel ip={ip} />
              </button>
            ))}
            {detection.usernames.slice(0, 12).map((u) => (
              <button
                key={`u-${u}`}
                type="button"
                className="entity"
                onClick={() => actions.pivot({ usernames: [u] })}
                title="Show all events for this username"
              >
                <Icon name="filter" size={12} /> <span className="mono">{u}</span>
              </button>
            ))}
            {detection.sourceIps.length + detection.usernames.length > 24 && (
              <span className="muted small">and more…</span>
            )}
          </div>
        )}
        <div className="button-row">
          {window && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => actions.pivot({ timeRange: window })}
            >
              <Icon name="clock" /> Events ±15 min around this detection
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => actions.pivot({ ruleIds: [detection.ruleId] })}
          >
            <Icon name="list" /> Events behind rule {detection.ruleId}
          </button>
        </div>
      </section>

      <section className="detail-section">
        <h3 className="section-title">Supporting events</h3>
        {evidence.error && <p className="text-danger">{evidence.error}</p>}
        {evidence.data && (
          <>
            <EventTable
              rows={evidence.data.rows}
              caption="Supporting events"
              compact
              onSelect={(e) => {
                actions.dispatch({ type: 'selectEvent', id: e.id });
                actions.navigate('events');
              }}
            />
            <Pagination
              page={evidence.data.page}
              pageSize={evidence.data.pageSize}
              total={evidence.data.total}
              onPage={setPage}
              label="Supporting event pages"
            />
          </>
        )}
      </section>

      {related.length > 0 && (
        <section className="detail-section">
          <h3 className="section-title">Related detections</h3>
          <ul className="mini-list">
            {related.map((d) => (
              <li key={d.id}>
                <button
                  type="button"
                  className="mini-item"
                  onClick={() => actions.dispatch({ type: 'selectDetection', id: d.id })}
                >
                  <SeverityBadge severity={d.severity} />
                  <span className="mini-main">
                    <span className="mini-title">{d.title}</span>
                    <span className="mini-sub">{d.ruleId}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="detail-section">
        <h3 className="section-title">Suggested next steps</h3>
        <ol className="steps">
          {detection.recommendations.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ol>
      </section>

      <section className="detail-section two-col">
        <div>
          <h3 className="section-title">Limitations</h3>
          <ul>
            {detection.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="section-title">Likely false-positive causes</h3>
          <ul>
            {detection.falsePositives.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
          {detection.mitre.length > 0 && (
            <>
              <h3 className="section-title">Related MITRE ATT&amp;CK techniques</h3>
              <p className="muted small">Context for the observed pattern, not attribution.</p>
              <ul>
                {detection.mitre.map((m) => (
                  <li key={m.id}>
                    <span className="mono">{m.id}</span> {m.name}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </section>

      <section className="detail-section">
        <label className="section-title" htmlFor="alert-note">
          Analyst note
        </label>
        <p className="muted small">
          Kept in memory for this session only; cleared when you load new data or close the tab.
        </p>
        <textarea
          id="alert-note"
          className="textarea"
          rows={4}
          maxLength={10_000}
          value={note}
          onChange={(e) =>
            actions.dispatch({ type: 'setNote', id: detection.id, note: e.target.value })
          }
        />
      </section>
    </article>
  );
}
