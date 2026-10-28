import { useEffect, useRef, useState } from 'react';
import { useApp } from '../../app/AppContext';
import { classifyIp, IP_CLASS_LABELS } from '../../features/log-ingestion/normalization/ip';
import { useWorkerQuery } from '../../hooks/useWorkerQuery';
import type { EventRow, RelatedBy } from '../../types/analytics';
import { escapeInvisible } from '../../utils/text';
import { SeverityBadge } from '../common/Badges';
import { Icon } from '../common/Icon';
import { EmptyState, Time } from '../common/Misc';
import { EventTable } from './EventTable';

const WINDOW_MINUTES = 5;

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className="kv-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export function EventDetail({
  event,
  onClose,
  onSelect,
}: {
  event: EventRow;
  onClose: () => void;
  onSelect: (e: EventRow) => void;
}) {
  const { state, actions, client } = useApp();
  // Open on the first relation this event actually has.
  const [by, setBy] = useState<RelatedBy>(
    event.sourceIp ? 'ip' : event.username ? 'user' : 'window',
  );
  const related = useWorkerQuery(
    `${state.summary?.completedAt}|${event.id}|${by}|${state.detectionsVersion}`,
    () =>
      client.query({
        type: 'related',
        eventId: event.id,
        by,
        windowMinutes: WINDOW_MINUTES,
        limit: 50,
      }),
  );
  const closeRef = useRef<HTMLButtonElement>(null);
  // Move focus into the panel when it opens (Escape or the close button return it to the row).
  useEffect(() => closeRef.current?.focus(), []);
  const linked = state.detections.filter((d) => event.detectionIds.includes(d.id));
  const ipClass = event.sourceIp ? classifyIp(event.sourceIp) : undefined;

  const pivot = () => {
    if (by === 'ip' && event.sourceIp) actions.pivot({ sourceIps: [event.sourceIp] });
    else if (by === 'user' && event.username) actions.pivot({ usernames: [event.username] });
    else if (by === 'window' && event.timestamp !== undefined) {
      actions.pivot({
        timeRange: {
          start: event.timestamp - WINDOW_MINUTES * 60_000,
          end: event.timestamp + WINDOW_MINUTES * 60_000,
        },
      });
    }
  };

  return (
    <section
      className="card detail-panel drawer"
      aria-labelledby="event-detail-title"
      onKeyDown={(e) => {
        if (e.key === 'Escape') onClose();
      }}
    >
      <header className="card-header">
        <div>
          <h2 className="card-title" id="event-detail-title">
            Event #{event.id} · line {event.line}
          </h2>
          <p className="card-sub">
            {event.category} · <span className="mono">{event.action}</span> ·{' '}
            {event.status === 'partial' ? 'partially parsed' : 'parsed'}
          </p>
        </div>
        <button
          ref={closeRef}
          type="button"
          className="icon-btn"
          onClick={onClose}
          aria-label="Close event details"
        >
          <Icon name="x" />
        </button>
      </header>

      {event.issues && event.issues.length > 0 && (
        <div className="callout callout-warn" role="note">
          <strong>Parsing issues: </strong>
          {event.issues.join('; ')}
        </div>
      )}

      <dl className="kv">
        <Field label="Timestamp" value={<Time ms={event.timestamp} />} />
        <Field
          label="Timestamp as logged"
          value={event.timestampRaw && <span className="mono">{event.timestampRaw}</span>}
        />
        <Field label="Format" value={event.format} />
        <Field
          label="Source IP"
          value={
            event.sourceIp && (
              <>
                <span className="mono">{event.sourceIp}</span>{' '}
                <span className="muted small">({IP_CLASS_LABELS[ipClass!]})</span>
              </>
            )
          }
        />
        <Field
          label="Username"
          value={event.username && <span className="mono">{event.username}</span>}
        />
        <Field label="Host" value={event.host && <span className="mono">{event.host}</span>} />
        <Field label="Auth outcome" value={event.auth?.outcome} />
        <Field label="Auth method" value={event.auth?.method} />
        <Field
          label="Account reported invalid"
          value={event.auth?.invalidUser ? 'yes' : undefined}
        />
        <Field
          label="Program"
          value={
            event.auth?.program &&
            `${event.auth.program}${event.auth.pid !== undefined ? `[${event.auth.pid}]` : ''}`
          }
        />
        <Field label="Source port" value={event.auth?.port} />
        <Field label="Target user" value={event.auth?.targetUser} />
        <Field label="HTTP method" value={event.http?.method} />
        <Field
          label="Path"
          value={event.http?.path && <span className="mono break">{event.http.path}</span>}
        />
        <Field
          label="Query"
          value={event.http?.query && <span className="mono break">{event.http.query}</span>}
        />
        <Field label="Status" value={event.http?.status} />
        <Field label="Bytes" value={event.http?.bytes?.toLocaleString('en-US')} />
        <Field
          label="Referrer"
          value={event.http?.referrer && <span className="mono break">{event.http.referrer}</span>}
        />
        <Field
          label="User agent"
          value={
            event.http?.userAgent && <span className="mono break">{event.http.userAgent}</span>
          }
        />
        <Field label="Source severity" value={event.sourceSeverity} />
        <Field
          label="Repeated message"
          value={event.repeat && `${event.repeat.index} of ${event.repeat.of}`}
        />
        {event.fields?.map(([k, v]) => (
          <Field key={`f-${k}`} label={k} value={<span className="mono break">{v}</span>} />
        ))}
      </dl>

      <h3 className="section-title">Original log line</h3>
      <p className="muted small">
        Shown as plain text. Control and bidirectional characters are displayed as escapes. Links
        are never followed.
      </p>
      <pre className="raw-line">{escapeInvisible(event.raw)}</pre>

      {linked.length > 0 && (
        <>
          <h3 className="section-title">Supports {linked.length} detection(s)</h3>
          <ul className="mini-list">
            {linked.map((d) => (
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
                    <span className="mini-sub">{d.ruleId}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      <h3 className="section-title">Related events</h3>
      <div className="tabs" role="tablist" aria-label="Relation">
        {(
          [
            ['ip', 'Same source IP', !event.sourceIp],
            ['user', 'Same username', !event.username],
            ['window', `±${WINDOW_MINUTES} minutes`, event.timestamp === undefined],
          ] as const
        ).map(([key, label, disabled]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={by === key}
            className={`tab${by === key ? ' active' : ''}`}
            disabled={disabled}
            onClick={() => setBy(key)}
          >
            {label}
          </button>
        ))}
      </div>
      {related.loading && <p className="muted">Loading related events…</p>}
      {related.error && <p className="text-danger">{related.error}</p>}
      {related.data && (
        <>
          <p className="muted small">
            {related.data.page.total.toLocaleString('en-US')} event(s) with{' '}
            {related.data.description}
            {related.data.page.total > related.data.page.rows.length
              ? `; showing the first ${related.data.page.rows.length}`
              : ''}
            .
          </p>
          {related.data.page.rows.length > 0 ? (
            <>
              <EventTable
                rows={related.data.page.rows}
                onSelect={onSelect}
                caption="Related events"
                compact
              />
              <button type="button" className="btn btn-sm" onClick={pivot}>
                <Icon name="filter" /> Filter all views by this relation
              </button>
            </>
          ) : (
            <EmptyState
              title={
                related.data.description.endsWith('.')
                  ? related.data.description
                  : 'No related events.'
              }
            />
          )}
        </>
      )}
    </section>
  );
}
