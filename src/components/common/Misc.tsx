import type { ReactNode } from 'react';
import { useApp } from '../../app/AppContext';
import { classifyIp, IP_CLASS_LABELS } from '../../features/log-ingestion/normalization/ip';
import { formatTimestamp } from '../../utils/format';

/** An empty block keeps its frame and says, in one sentence, why it is empty. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state" role="status">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Time({ ms }: { ms: number | undefined }) {
  const { state } = useApp();
  const text = formatTimestamp(ms, state.timeZone);
  return ms === undefined ? (
    <span className="muted">no timestamp</span>
  ) : (
    <time dateTime={new Date(ms).toISOString()}>{text}</time>
  );
}

/** IP with address-space context. Classification is about the address plan, not intent. */
export function IpLabel({ ip }: { ip: string }) {
  const cls = classifyIp(ip);
  return (
    <span className="ip-label">
      <span className="mono">{ip}</span>
      {cls !== 'public' && (
        <span className="tag" title={IP_CLASS_LABELS[cls]}>
          {cls}
        </span>
      )}
    </span>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
  label,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  label: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : page * pageSize + 1;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <nav className="pagination" aria-label={label}>
      <span className="muted">
        {from.toLocaleString('en-US')}–{to.toLocaleString('en-US')} of{' '}
        {total.toLocaleString('en-US')}
      </span>
      <div className="pagination-buttons">
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => onPage(0)}
          disabled={page === 0}
        >
          First
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => onPage(page - 1)}
          disabled={page === 0}
        >
          Previous
        </button>
        <span className="muted" aria-live="polite">
          Page {page + 1} of {pages}
        </span>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => onPage(page + 1)}
          disabled={page >= pages - 1}
        >
          Next
        </button>
      </div>
    </nav>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Callout({
  tone = 'info',
  children,
  title,
}: {
  tone?: 'info' | 'warn' | 'danger' | 'success';
  children: ReactNode;
  title?: string;
}) {
  return (
    <div className={`callout callout-${tone}`} role={tone === 'danger' ? 'alert' : 'note'}>
      {title && <strong>{title} </strong>}
      {children}
    </div>
  );
}
