export interface TooltipRow {
  label: string;
  value: string | number;
  color?: string;
}

/** Tooltip body: label in text ink, a colour swatch beside each value for identity. */
export function TooltipBox({ title, rows }: { title: string; rows: TooltipRow[] }) {
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{title}</div>
      {rows.map((r) => (
        <div className="chart-tooltip-row" key={r.label}>
          {r.color && (
            <span className="swatch" style={{ background: r.color }} aria-hidden="true" />
          )}
          <span className="chart-tooltip-label">{r.label}</span>
          <span className="chart-tooltip-value">
            {typeof r.value === 'number' ? r.value.toLocaleString('en-US') : r.value}
          </span>
        </div>
      ))}
    </div>
  );
}
