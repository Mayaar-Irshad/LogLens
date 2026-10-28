import type { EventRow, EventSort, SortField } from '../../types/analytics';
import { toSingleLine, truncate } from '../../utils/text';
import { SeverityBadge } from '../common/Badges';
import { Time } from '../common/Misc';

function eventSummary(e: EventRow): string {
  if (e.http) {
    const req =
      e.http.method || e.http.path
        ? `${e.http.method ?? '-'} ${e.http.path ?? ''}${e.http.query ? `?${e.http.query}` : ''}`
        : (e.fields?.find(([k]) => k === 'request')?.[1] ?? 'request');
    return req;
  }
  return e.message ?? e.action;
}

function outcomeCell(e: EventRow) {
  if (e.http?.status !== undefined)
    return (
      <span className={`code code-${Math.floor(e.http.status / 100)}xx`}>{e.http.status}</span>
    );
  if (e.auth?.outcome)
    return <span className={`outcome outcome-${e.auth.outcome}`}>{e.auth.outcome}</span>;
  return <span className="muted">—</span>;
}

const COLUMNS: Array<{ label: string; field?: SortField; className?: string }> = [
  { label: 'Time', field: 'timestamp' },
  { label: 'Flag' },
  { label: 'Action', field: 'action' },
  { label: 'Source IP', field: 'sourceIp' },
  { label: 'User', field: 'username' },
  { label: 'Result', field: 'status' },
  { label: 'Request / message' },
  { label: 'Line', field: 'line', className: 'num' },
];

export function EventTable({
  rows,
  sort,
  onSort,
  onSelect,
  selectedId,
  caption,
  compact = false,
}: {
  rows: EventRow[];
  sort?: EventSort;
  onSort?: (sort: EventSort) => void;
  onSelect?: (row: EventRow) => void;
  selectedId?: number | null;
  caption: string;
  compact?: boolean;
}) {
  return (
    <div className="table-wrap">
      <table className={`table event-table${compact ? ' compact' : ''}`}>
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {COLUMNS.map((c) => {
              const active = sort && c.field === sort.field;
              return (
                <th
                  key={c.label}
                  scope="col"
                  className={c.className}
                  aria-sort={
                    active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : undefined
                  }
                >
                  {c.field && onSort && sort ? (
                    <button
                      type="button"
                      className="sort-button"
                      onClick={() =>
                        onSort({
                          field: c.field!,
                          direction: active && sort.direction === 'asc' ? 'desc' : 'asc',
                        })
                      }
                    >
                      {c.label}
                      <span aria-hidden="true">
                        {active ? (sort.direction === 'asc' ? ' ▲' : ' ▼') : ''}
                      </span>
                    </button>
                  ) : (
                    c.label
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr
              key={e.id}
              className={selectedId === e.id ? 'selected' : undefined}
              onClick={onSelect ? () => onSelect(e) : undefined}
            >
              <td className="nowrap">
                {onSelect ? (
                  <button
                    type="button"
                    className="link-button"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      onSelect(e);
                    }}
                    aria-label={`Open event ${e.id} details`}
                    data-event-open={e.id}
                  >
                    <Time ms={e.timestamp} />
                  </button>
                ) : (
                  <Time ms={e.timestamp} />
                )}
              </td>
              <td>
                {e.maxSeverity ? (
                  <SeverityBadge severity={e.maxSeverity} />
                ) : e.status === 'partial' ? (
                  <span className="tag tag-warn">partial</span>
                ) : null}
              </td>
              <td className="mono small">{e.action}</td>
              <td className="mono">{e.sourceIp ?? <span className="muted">—</span>}</td>
              <td className="mono">
                {e.username ? truncate(e.username, 32) : <span className="muted">—</span>}
              </td>
              <td>{outcomeCell(e)}</td>
              <td className="mono small cell-message" title={toSingleLine(eventSummary(e))}>
                {truncate(toSingleLine(eventSummary(e)), compact ? 70 : 110)}
              </td>
              <td className="num muted">{e.line}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
