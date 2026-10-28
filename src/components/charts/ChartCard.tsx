import { useId, useState, type ReactNode } from 'react';
import { EmptyState } from '../common/Misc';
import { Icon } from '../common/Icon';

export interface TableColumn<T> {
  header: string;
  cell: (row: T) => ReactNode;
  numeric?: boolean;
}

/**
 * Card wrapper shared by every chart: title, description, empty state, an
 * accessible summary, and a "table" view with the exact plotted values as the
 * non-visual alternative.
 */
export function ChartCard<T>({
  title,
  description,
  summary,
  empty,
  emptyText,
  rows,
  columns,
  children,
  hint,
  headerExtra,
  fill,
  className = '',
}: {
  title: string;
  description?: string;
  /** One-sentence text alternative read by screen readers. */
  summary: string;
  empty: boolean;
  emptyText: string;
  rows: T[];
  columns: Array<TableColumn<T>>;
  children: ReactNode;
  hint?: string;
  /** Legend or other context shown in the card header. */
  headerExtra?: ReactNode;
  /**
   * Minimum plot height for a chart that grows into the card's spare height,
   * so cards sharing a row keep no blank band. Its child sizes to 100%.
   */
  fill?: number;
  className?: string;
}) {
  const [asTable, setAsTable] = useState(false);
  const id = useId();
  return (
    <section className={`card chart-card ${className}`} aria-labelledby={`${id}-title`}>
      <header className="card-header">
        <div>
          <h2 className="card-title" id={`${id}-title`}>
            {title}
          </h2>
          {description && <p className="card-sub">{description}</p>}
        </div>
        {!empty && (
          <div className="card-header-tools">
            {!asTable && headerExtra}
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              aria-pressed={asTable}
              onClick={() => setAsTable((v) => !v)}
              title={asTable ? 'Show chart' : 'Show data as a table'}
            >
              <Icon name={asTable ? 'chart' : 'table'} />
              <span>{asTable ? 'Chart' : 'Table'}</span>
            </button>
          </div>
        )}
      </header>
      {empty ? (
        <EmptyState title={emptyText} />
      ) : asTable ? (
        <div className="table-wrap chart-table">
          <table className="table">
            <caption className="visually-hidden">{title}</caption>
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c.header} scope="col" className={c.numeric ? 'num' : undefined}>
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i}>
                  {columns.map((c) => (
                    <td key={c.header} className={c.numeric ? 'num' : undefined}>
                      {c.cell(row)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <div
            className={fill ? 'chart-body chart-fill' : 'chart-body'}
            {...(fill ? { style: { minHeight: fill } } : {})}
            role="img"
            aria-label={summary}
          >
            {children}
          </div>
          {hint && <p className="chart-hint">{hint}</p>}
        </>
      )}
    </section>
  );
}
