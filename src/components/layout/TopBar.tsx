import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { LOG_FORMAT_LABELS } from '../../types/events';
import { formatBytes, formatDuration, formatOffset, formatTimestamp } from '../../utils/format';
import { toSingleLine, truncate } from '../../utils/text';
import { Icon } from '../common/Icon';

export function TopBar() {
  const { state, actions, workerMode } = useApp();
  const s = state.summary;
  const range = state.baseMetrics?.timeRange;
  const localOffset = formatOffset(-new Date().getTimezoneOffset());
  const [confirming, setConfirming] = useState(false);
  const work =
    Object.values(state.statuses).filter((v) => v !== 'open').length +
    Object.values(state.notes).filter((v) => v.trim() !== '').length +
    (state.caseNote.trim() ? 1 : 0);
  const startOver = () => {
    setConfirming(false);
    actions.newScan();
  };
  return (
    <header className="topbar">
      <div className="topbar-meta">
        <div className="dataset">
          <span className="dataset-icon">
            <Icon name="file" />
          </span>
          {s ? (
            <div className="dataset-text">
              <div className="dataset-title">
                <span className="dataset-name" title={toSingleLine(s.source.name)}>
                  {truncate(toSingleLine(s.source.name), 48)}
                </span>
                <span className="tag">{LOG_FORMAT_LABELS[s.format]}</span>
              </div>
              <div className="dataset-meta">
                <span className="meta-item">{formatBytes(s.source.sizeBytes)}</span>
                <span className="meta-item">
                  {s.stats.eventsCreated.toLocaleString('en-US')} events
                </span>
                {range?.start !== undefined && range.end !== undefined && (
                  <span className="meta-item">
                    {formatTimestamp(range.start, state.timeZone)} →{' '}
                    {formatTimestamp(range.end, state.timeZone)} (
                    {formatDuration(range.end - range.start)})
                  </span>
                )}
              </div>
            </div>
          ) : (
            <span className="muted">No dataset loaded</span>
          )}
        </div>
        {workerMode === 'in-process' && (
          <span className="tag tag-warn">
            Web Workers unavailable: analysis runs on the page thread
          </span>
        )}
      </div>
      <div className="topbar-actions">
        <div className="segmented" role="group" aria-label="Display time zone">
          {(['UTC', 'local'] as const).map((tz) => (
            <button
              key={tz}
              type="button"
              aria-pressed={state.timeZone === tz}
              className={state.timeZone === tz ? 'active' : ''}
              onClick={() => actions.dispatch({ type: 'setTimeZone', timeZone: tz })}
              title={
                tz === 'UTC'
                  ? 'Show all times in UTC'
                  : `Show times in this browser's zone (${localOffset})`
              }
            >
              {tz === 'UTC' ? 'UTC' : `Local (${localOffset})`}
            </button>
          ))}
        </div>
        {s && !confirming && (
          <button
            type="button"
            className="btn"
            onClick={() => (work > 0 ? setConfirming(true) : startOver())}
          >
            <Icon name="refresh" size={14} />
            New scan
          </button>
        )}
        {s && confirming && (
          <span className="confirm" role="alert">
            <span>
              Discard this dataset and {work} review{work === 1 ? '' : 's'} or note
              {work === 1 ? '' : 's'}?
            </span>
            <button type="button" className="btn btn-danger btn-sm" onClick={startOver}>
              Discard and start over
            </button>
            <button type="button" className="btn btn-sm" onClick={() => setConfirming(false)}>
              Keep
            </button>
          </span>
        )}
      </div>
    </header>
  );
}
