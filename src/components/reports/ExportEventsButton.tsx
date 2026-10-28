import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { buildFilename, downloadText } from '../../utils/download';
import { Icon } from '../common/Icon';

/** Export the currently filtered events as CSV (raw log lines excluded unless requested). */
export function ExportEventsButton({
  includeRaw = false,
  label = 'Export filtered events (CSV)',
}: {
  includeRaw?: boolean;
  label?: string;
}) {
  const { state, client, eventFilter } = useApp();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await client.query({
        type: 'exportEvents',
        filter: eventFilter,
        includeRaw,
        timeZone: state.timeZone,
      });
      const now = Date.now();
      downloadText(
        buildFilename('events', state.summary?.source.name ?? 'logs', now, 'csv'),
        result.csv,
        'text/csv',
      );
      setMessage(
        `${result.rows.toLocaleString('en-US')} rows exported${result.truncated ? ' (truncated at the export limit)' : ''}.`,
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Export failed.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="export-button">
      <button type="button" className="btn" onClick={() => void run()} disabled={busy}>
        <Icon name="download" /> {busy ? 'Exporting…' : label}
      </button>
      {message && (
        <span className="muted small" role="status">
          {message}
        </span>
      )}
    </span>
  );
}
