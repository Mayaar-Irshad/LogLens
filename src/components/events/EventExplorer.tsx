import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { useWorkerQuery } from '../../hooks/useWorkerQuery';
import { EVENT_CATEGORIES } from '../../types/events';
import { SEVERITIES } from '../../types/detection';
import type { EventRow, EventSort, StatusClass } from '../../types/analytics';
import { normalizeIp } from '../../features/log-ingestion/normalization/ip';
import { EmptyState, PageHeader, Pagination } from '../common/Misc';
import { EventDetail } from './EventDetail';
import { EventTable } from './EventTable';
import { ExportEventsButton } from '../reports/ExportEventsButton';

const PAGE_SIZES = [25, 50, 100];

function AddValue({
  label,
  placeholder,
  onAdd,
  validate,
}: {
  label: string;
  placeholder: string;
  onAdd: (v: string) => void;
  validate?: (v: string) => string | null;
}) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const id = `add-${label.replace(/\W/g, '')}`;
  return (
    <form
      className="add-value"
      onSubmit={(e) => {
        e.preventDefault();
        const v = value.trim();
        if (!v) return;
        const problem = validate?.(v) ?? null;
        setError(problem);
        if (problem) return;
        onAdd(v);
        setValue('');
      }}
    >
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <div className="add-value-row">
        <input
          id={id}
          className="input"
          value={value}
          placeholder={placeholder}
          maxLength={256}
          onChange={(e) => setValue(e.target.value)}
          aria-invalid={error !== null}
        />
        <button type="submit" className="btn btn-sm">
          Add
        </button>
      </div>
      {error && <span className="field-hint text-danger">{error}</span>}
    </form>
  );
}

export function EventExplorer() {
  const { state, actions, client, eventFilter } = useApp();
  const [sort, setSort] = useState<EventSort>({ field: 'timestamp', direction: 'asc' });
  const [pageSize, setPageSize] = useState(50);
  const filterKey = JSON.stringify(eventFilter);
  // The page belongs to one filter/sort/size combination; any change starts again at page 0.
  const pagingKey = `${filterKey}|${sort.field}|${sort.direction}|${pageSize}`;
  const [paging, setPaging] = useState({ key: pagingKey, page: 0 });
  const page = paging.key === pagingKey ? paging.page : 0;
  const setPage = (p: number) => setPaging({ key: pagingKey, page: p });

  const result = useWorkerQuery(
    `${state.summary?.completedAt}|${pagingKey}|${page}|${state.detectionsVersion}`,
    () => client.query({ type: 'events', filter: eventFilter, sort, page, pageSize }),
  );

  // The selected event lives in app state so other views (alert evidence, related events) can open it.
  const selectedId = state.selectedEventId;
  const selectedQuery = useWorkerQuery(
    selectedId === null
      ? null
      : `${state.summary?.completedAt}|event|${selectedId}|${state.detectionsVersion}`,
    () => client.query({ type: 'eventsById', ids: [selectedId!] }),
  );
  const selected =
    selectedId === null ? null : (selectedQuery.data?.find((e) => e.id === selectedId) ?? null);
  const select = (e: EventRow | null) =>
    actions.dispatch({ type: 'selectEvent', id: e?.id ?? null });
  const close = () => {
    const id = selectedId;
    select(null);
    // Return focus to the row the panel was opened from.
    requestAnimationFrame(() =>
      document.querySelector<HTMLButtonElement>(`[data-event-open="${id}"]`)?.focus(),
    );
  };

  const f = state.filters;
  // A select shows one value; when several are active (set from a chart or the
  // detections view) it says so instead of pretending nothing is selected.
  const single = <T,>(list: T[]): T | '' | '__multiple' =>
    list.length === 1 ? list[0]! : list.length > 1 ? '__multiple' : '';
  const multiple = (count: number) =>
    count > 1 ? (
      <option value="__multiple" disabled>
        {count} selected
      </option>
    ) : null;
  const addOnly = <K extends 'sourceIps' | 'usernames' | 'httpStatuses'>(
    key: K,
    value: (typeof f)[K][number],
  ) => {
    if (!(f[key] as unknown[]).includes(value)) actions.toggleFilter(key, value);
  };

  return (
    <div className="view">
      <PageHeader
        title="Event explorer"
        description="Every parsed event, including partially parsed records. Sorting and filtering never modify the underlying data."
        actions={<ExportEventsButton />}
      />
      <section className="card explorer-filters" aria-label="Event filters">
        <div className="field">
          <label className="field-label" htmlFor="ex-category">
            Event type
          </label>
          <select
            id="ex-category"
            className="select"
            value={single(f.categories)}
            onChange={(e) =>
              actions.setFilters({
                ...f,
                categories: e.target.value
                  ? [e.target.value as (typeof EVENT_CATEGORIES)[number]]
                  : [],
              })
            }
          >
            <option value="">All types</option>
            {multiple(f.categories.length)}
            {EVENT_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="ex-outcome">
            Auth outcome
          </label>
          <select
            id="ex-outcome"
            className="select"
            value={single(f.authOutcomes)}
            onChange={(e) =>
              actions.setFilters({
                ...f,
                authOutcomes: e.target.value ? [e.target.value as 'success' | 'failure'] : [],
              })
            }
          >
            <option value="">Any</option>
            {multiple(f.authOutcomes.length)}
            <option value="failure">failure</option>
            <option value="success">success</option>
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="ex-class">
            HTTP status class
          </label>
          <select
            id="ex-class"
            className="select"
            value={single(f.statusClasses)}
            onChange={(e) =>
              actions.setFilters({
                ...f,
                statusClasses: e.target.value ? [e.target.value as StatusClass] : [],
              })
            }
          >
            <option value="">Any</option>
            {multiple(f.statusClasses.length)}
            {(['2xx', '3xx', '4xx', '5xx'] as const).map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="ex-sev">
            Detection severity
          </label>
          <select
            id="ex-sev"
            className="select"
            value={single(f.severities)}
            onChange={(e) =>
              actions.setFilters({
                ...f,
                severities: e.target.value ? [e.target.value as (typeof SEVERITIES)[number]] : [],
              })
            }
          >
            <option value="">Any (including unflagged)</option>
            {multiple(f.severities.length)}
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                flagged {s}
              </option>
            ))}
          </select>
        </div>
        <AddValue
          label="Source IP"
          placeholder="203.0.113.50"
          validate={(v) => (normalizeIp(v) ? null : 'Not a valid IP address')}
          onAdd={(v) => addOnly('sourceIps', normalizeIp(v)!)}
        />
        <AddValue label="Username" placeholder="root" onAdd={(v) => addOnly('usernames', v)} />
        <AddValue
          label="HTTP status"
          placeholder="404"
          validate={(v) => (/^[1-5]\d\d$/.test(v) ? null : 'Use a 3-digit status code')}
          onAdd={(v) => addOnly('httpStatuses', Number(v))}
        />
      </section>

      <div className={`explorer${selectedId !== null ? ' with-detail' : ''}`}>
        <section className="card" aria-label="Events">
          <div className="table-toolbar">
            <span className="muted" aria-live="polite">
              {result.data
                ? `${result.data.total.toLocaleString('en-US')} matching events`
                : result.loading
                  ? 'Loading…'
                  : ''}
            </span>
            <label className="inline-field">
              Rows per page
              <select
                className="select select-sm"
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {result.error && <p className="text-danger">{result.error}</p>}
          {result.data && result.data.total === 0 && (
            <EmptyState title="No events match the current filters." />
          )}
          {result.data && result.data.total > 0 && (
            <>
              <EventTable
                rows={result.data.rows}
                sort={sort}
                onSort={setSort}
                onSelect={select}
                selectedId={selectedId}
                caption="Parsed events"
              />
              <Pagination
                page={result.data.page}
                pageSize={result.data.pageSize}
                total={result.data.total}
                onPage={setPage}
                label="Event pages"
              />
            </>
          )}
        </section>
        {selected && (
          <EventDetail key={selected.id} event={selected} onClose={close} onSelect={select} />
        )}
      </div>
    </div>
  );
}
