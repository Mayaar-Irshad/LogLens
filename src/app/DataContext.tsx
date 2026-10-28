import { createContext, useContext, useMemo, type ReactNode } from 'react';
import { filterDetections, hasActiveFilters, statusOf } from '../features/investigation/filters';
import { useWorkerQuery } from '../hooks/useWorkerQuery';
import type { DashboardMetrics } from '../types/analytics';
import type { DetectionSummary } from '../types/detection';
import { useApp } from './AppContext';

interface DataContextValue {
  /** Metrics for the current filters (falls back to the unfiltered metrics while loading). */
  metrics: DashboardMetrics | null;
  loading: boolean;
  error: string | null;
  filtered: boolean;
  /** Detections visible under the current filters. */
  detections: DetectionSummary[];
  openCount: number;
}

const DataContext = createContext<DataContextValue | null>(null);

/**
 * Single source of truth for filtered data. One metrics query per filter
 * change feeds every chart, counter and alert list, so they cannot disagree.
 */
export function DataProvider({ children }: { children: ReactNode }) {
  const { state, client, eventFilter } = useApp();
  const ready = state.scan.phase === 'ready' && state.summary !== null;
  const filtered = hasActiveFilters(state.filters);
  const needsQuery = ready && (filtered || state.timeZone !== state.baseMetricsTimeZone);
  const key = needsQuery
    ? `${state.summary?.completedAt}|${JSON.stringify(eventFilter)}|${state.detectionsVersion}`
    : null;
  const query = useWorkerQuery(
    key,
    () => client.query({ type: 'metrics', filter: eventFilter }),
    60,
  );

  const value = useMemo<DataContextValue>(() => {
    const inScope = needsQuery ? (query.data?.detectionIdsInScope ?? null) : null;
    const detections = ready
      ? filterDetections(state.detections, state.filters, state.statuses, inScope)
      : [];
    return {
      // While a new filter is being evaluated, keep showing the previous result (the
      // filter bar shows "Updating…") instead of unmounting every chart.
      metrics: needsQuery ? (query.data?.metrics ?? state.baseMetrics) : state.baseMetrics,
      loading: needsQuery && query.loading,
      error: query.error,
      filtered,
      detections,
      openCount: state.detections.filter((d) => statusOf(state.statuses, d.id) !== 'reviewed')
        .length,
    };
  }, [
    needsQuery,
    query,
    ready,
    state.detections,
    state.filters,
    state.statuses,
    state.baseMetrics,
    filtered,
  ]);

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export function useData(): DataContextValue {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used inside <DataProvider>');
  return ctx;
}
