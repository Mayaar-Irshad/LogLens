import { useEffect, useState } from 'react';
import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import {
  clearFilters,
  filterChips,
  hasActiveFilters,
  removeChip,
} from '../../features/investigation/filters';
import { formatTimestamp, fromDateTimeInput, HOUR_MS, toDateTimeInput } from '../../utils/format';
import { truncate } from '../../utils/text';
import { Icon } from '../common/Icon';

/** Ranges measured back from the last event in the dataset (not from "now"). */
const PRESETS: Array<{ label: string; ms: number }> = [
  { label: 'Last 24 h', ms: 24 * HOUR_MS },
  { label: 'Last 6 h', ms: 6 * HOUR_MS },
  { label: 'Last 1 h', ms: HOUR_MS },
];

/** Global filter state shared by every analysis view. */
export function FilterBar() {
  const { state, actions } = useApp();
  const { loading, metrics, error } = useData();
  const f = state.filters;
  const tz = state.timeZone;
  const [search, setSearch] = useState(f.search);
  const [committed, setCommitted] = useState(f.search);
  const [customOpen, setCustomOpen] = useState(false);
  if (committed !== f.search) {
    // The committed search changed elsewhere (e.g. "Clear all"): adopt it.
    setCommitted(f.search);
    setSearch(f.search);
  }
  useEffect(() => {
    if (search === f.search) return;
    const t = setTimeout(() => actions.setFilters({ ...state.filters, search }), 300);
    return () => clearTimeout(t);
  }, [search, f.search, actions, state.filters]);

  const datasetStart = state.baseMetrics?.timeRange.start;
  const datasetEnd = state.baseMetrics?.timeRange.end;
  const span =
    datasetStart !== undefined && datasetEnd !== undefined ? datasetEnd - datasetStart : 0;
  const range = f.timeRange;
  const hasRange = range.start !== undefined || range.end !== undefined;
  const preset = !hasRange
    ? 'all'
    : (PRESETS.find(
        (p) =>
          datasetEnd !== undefined && range.end === datasetEnd && range.start === datasetEnd - p.ms,
      )?.label ?? 'custom');
  const showCustom = customOpen || preset === 'custom';

  const chips = filterChips(f, tz).filter((c) => c.key !== 'search');
  const active = hasActiveFilters(f);
  const setRange = (which: 'start' | 'end', value: string) => {
    const ms = value === '' ? undefined : fromDateTimeInput(value, tz);
    const next = { ...range };
    if (ms === undefined) delete next[which];
    else next[which] = which === 'end' ? ms + 999 : ms;
    // An inverted range would silently match nothing: swap the ends instead.
    if (next.start !== undefined && next.end !== undefined && next.start > next.end) {
      [next.start, next.end] = [next.end - 999, next.start + 999];
    }
    actions.setFilters({ ...f, timeRange: next });
  };
  const applyPreset = (ms: number | null) => {
    setCustomOpen(false);
    actions.setFilters({
      ...f,
      timeRange:
        ms === null || datasetEnd === undefined ? {} : { start: datasetEnd - ms, end: datasetEnd },
    });
  };

  return (
    <section className="filterbar" aria-label="Filters">
      <div className="filterbar-row">
        <label className="filter-search">
          <Icon name="search" />
          <span className="visually-hidden">Search original log lines</span>
          <input
            type="search"
            placeholder="Search raw log lines"
            value={search}
            maxLength={200}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
        {datasetEnd !== undefined && (
          <div className="filter-range">
            <span>Time</span>
            <div className="segmented" role="group" aria-label="Time range">
              <button
                type="button"
                className={preset === 'all' && !customOpen ? 'active' : ''}
                aria-pressed={preset === 'all' && !customOpen}
                onClick={() => applyPreset(null)}
              >
                All
              </button>
              {PRESETS.filter((p) => p.ms < span).map((p) => (
                <button
                  key={p.label}
                  type="button"
                  className={preset === p.label ? 'active' : ''}
                  aria-pressed={preset === p.label}
                  onClick={() => applyPreset(p.ms)}
                  title={`${p.label} of the data, ending at its last event`}
                >
                  {p.label}
                </button>
              ))}
              <button
                type="button"
                className={showCustom ? 'active' : ''}
                aria-pressed={showCustom}
                aria-expanded={showCustom}
                onClick={() => setCustomOpen((v) => !v || preset === 'custom')}
              >
                Custom
              </button>
            </div>
          </div>
        )}
        {showCustom && (
          <>
            <label className="filter-time">
              <span>From</span>
              <input
                type="datetime-local"
                step={1}
                value={toDateTimeInput(range.start, tz)}
                onChange={(e) => setRange('start', e.target.value)}
              />
            </label>
            <label className="filter-time">
              <span>To</span>
              <input
                type="datetime-local"
                step={1}
                value={toDateTimeInput(range.end, tz)}
                onChange={(e) => setRange('end', e.target.value)}
              />
            </label>
            <span className="muted small">{tz === 'UTC' ? 'UTC' : 'local time'}</span>
          </>
        )}
        <div className="filter-status" aria-live="polite">
          {error ? (
            <span className="text-danger">Filter query failed: {error}</span>
          ) : loading ? (
            <span className="muted">Updating…</span>
          ) : active && metrics ? (
            <span className="muted">
              {metrics.totalEvents.toLocaleString('en-US')} matching events
            </span>
          ) : null}
        </div>
        {active && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setCustomOpen(false);
              // Drop any search still waiting for its debounce, too.
              setSearch('');
              actions.setFilters(clearFilters());
            }}
          >
            Clear all filters
          </button>
        )}
      </div>
      {(chips.length > 0 || hasRange) && (
        <ul className="chips" aria-label="Active filters">
          {hasRange && (
            <li>
              <span className="chip">
                <span>
                  Time: {range.start !== undefined ? formatTimestamp(range.start, tz) : 'start'} →{' '}
                  {range.end !== undefined ? formatTimestamp(range.end, tz) : 'end'}
                </span>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label="Remove time range filter"
                  onClick={() => applyPreset(null)}
                >
                  <Icon name="x" size={12} />
                </button>
              </span>
            </li>
          )}
          {chips.map((chip) => (
            <li key={`${chip.key}:${chip.value}`}>
              <span className="chip">
                <span title={chip.label}>{truncate(chip.label, 60)}</span>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`Remove filter ${chip.label}`}
                  onClick={() => actions.setFilters(removeChip(f, chip))}
                >
                  <Icon name="x" size={12} />
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
