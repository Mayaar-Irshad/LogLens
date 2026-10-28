import type { RejectedRecord } from '../../types/events';
import type { ParseStats } from '../../types/ingestion';
import { formatBytes, formatPercent } from '../../utils/format';

const REASONS: Record<RejectedRecord['reason'], string> = {
  line_too_long: 'Line too long',
  unrecognized_format: 'Unrecognized format',
  invalid_json: 'Invalid JSON',
  not_an_object: 'Not a JSON object',
  csv_unterminated_quote: 'Unterminated CSV quote',
  csv_empty_record: 'Empty CSV record',
  record_too_large: 'Record too large',
};

/** Parsing statistics: every line is accounted for in exactly one bucket. */
export function ParseReport({
  stats,
  rejected,
  timingMs,
}: {
  stats: ParseStats;
  rejected: RejectedRecord[];
  timingMs?: number;
}) {
  const records = stats.parsedRecords + stats.partialRecords + stats.rejectedRecords;
  const items: Array<{ label: string; value: number; note?: string; tone?: string }> = [
    { label: 'Lines read', value: stats.totalLines },
    {
      label: 'Parsed',
      value: stats.parsedRecords,
      note: formatPercent(stats.parsedRecords, records),
      tone: 'ok',
    },
    {
      label: 'Partially parsed',
      value: stats.partialRecords,
      note: formatPercent(stats.partialRecords, records),
      tone: stats.partialRecords ? 'warn' : '',
    },
    {
      label: 'Rejected',
      value: stats.rejectedRecords,
      note: formatPercent(stats.rejectedRecords, records),
      tone: stats.rejectedRecords ? 'bad' : '',
    },
    { label: 'Blank / skipped', value: stats.blankLines + stats.skippedLines },
    { label: 'Events created', value: stats.eventsCreated },
    { label: 'Duplicate lines (kept)', value: stats.duplicateLines },
    {
      label: 'Not analyzed (limit)',
      value: stats.unprocessedLines,
      tone: stats.unprocessedLines ? 'warn' : '',
    },
  ];
  return (
    <section className="card" aria-labelledby="parse-report-title">
      <header className="card-header">
        <div>
          <h2 className="card-title" id="parse-report-title">
            Parsing report
          </h2>
          <p className="card-sub">
            {formatBytes(stats.bytesRead)} read
            {timingMs !== undefined ? ` in ${(timingMs / 1000).toFixed(2)} s` : ''}. Records are
            never silently dropped: each line is parsed, partially parsed, rejected, skipped or
            explicitly not analyzed.
          </p>
        </div>
      </header>
      <dl className="stat-grid">
        {items.map((i) => (
          <div key={i.label} className={`stat ${i.tone ? `stat-${i.tone}` : ''}`}>
            <dt>{i.label}</dt>
            <dd>
              {i.value.toLocaleString('en-US')}
              {i.note && <span className="stat-note"> {i.note}</span>}
            </dd>
          </div>
        ))}
      </dl>
      {stats.warnings.length > 0 && (
        <div className="warnings">
          <h3>Warnings and assumptions</h3>
          <ul>
            {stats.warnings.map((w) => (
              <li key={w.code}>{w.message}</li>
            ))}
          </ul>
        </div>
      )}
      {stats.rejectedRecords > 0 && (
        <details className="rejected">
          <summary>
            Inspect rejected records ({rejected.length.toLocaleString('en-US')} of{' '}
            {stats.rejectedRecords.toLocaleString('en-US')} kept as samples)
          </summary>
          <p className="muted small">
            Previews are truncated to 160 characters with control characters shown as escapes.
          </p>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col" className="num">
                    Line
                  </th>
                  <th scope="col">Reason</th>
                  <th scope="col">Detail</th>
                  <th scope="col">Preview</th>
                </tr>
              </thead>
              <tbody>
                {rejected.slice(0, 200).map((r) => (
                  <tr key={`${r.line}-${r.reason}`}>
                    <td className="num">{r.line}</td>
                    <td>{REASONS[r.reason]}</td>
                    <td>{r.detail}</td>
                    <td>
                      <details>
                        <summary>Show</summary>
                        <code className="mono preview">{r.preview}</code>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </section>
  );
}
