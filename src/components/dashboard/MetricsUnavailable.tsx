import { useApp } from '../../app/AppContext';
import { clearFilters } from '../../features/investigation/filters';
import { Callout, PageHeader } from '../common/Misc';

/**
 * Shown instead of a dashboard while its first metrics load, or when the
 * filtered query failed. A failed query never falls back to unfiltered data
 * under active filters, which would misrepresent what is on screen.
 */
export function MetricsUnavailable({ title, error }: { title: string; error: string | null }) {
  const { actions } = useApp();
  return (
    <div className="view">
      <PageHeader title={title} />
      {error ? (
        <Callout tone="danger" title="These figures could not be computed for the current filters.">
          {error}{' '}
          <button
            type="button"
            className="link-button"
            onClick={() => actions.setFilters(clearFilters())}
          >
            Clear filters
          </button>
        </Callout>
      ) : (
        <p className="muted" role="status">
          Computing figures…
        </p>
      )}
    </div>
  );
}
