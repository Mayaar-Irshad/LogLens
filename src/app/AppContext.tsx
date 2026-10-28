import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { validateDetectionConfig } from '../features/detection/config/detectionConfig';
import {
  clearFilters,
  toEventFilter,
  toggleFilterValue,
  type ArrayFilterKey,
} from '../features/investigation/filters';
import { isSampleId, SAMPLE_YEAR, sampleInfo } from '../features/sample-data/samples';
import type { DashboardFilters, EventFilter } from '../types/analytics';
import type { DetectionConfig } from '../types/detection';
import type { ParseOptions } from '../types/ingestion';
import {
  AnalysisCancelledError,
  AnalysisClient,
  type WorkerFactory,
} from '../workers/analysisClient';
import {
  createAnalysisWorker,
  createLazyInProcessWorker,
  supportsWorkers,
} from '../workers/createWorker';
import type { AnalyzeSource } from '../workers/protocol';
import { initialState, reducer, VIEWS, type Action, type AppState, type View } from './state';

function viewFromHash(hash: string): View | null {
  const v = hash.replace(/^#\/?/, '');
  return (VIEWS as readonly string[]).includes(v) ? (v as View) : null;
}

export interface AppActions {
  dispatch: (action: Action) => void;
  navigate: (view: View) => void;
  /** Resolves true when the scan completed. */
  startScan: (source: AnalyzeSource, parse: ParseOptions) => Promise<boolean>;
  cancelScan: () => void;
  newScan: () => void;
  applyDetectionConfig: (config: DetectionConfig) => Promise<void>;
  setFilters: (filters: DashboardFilters) => void;
  toggleFilter: <K extends ArrayFilterKey>(key: K, value: DashboardFilters[K][number]) => void;
  /** Replace filters with a pivot and open the event explorer. */
  pivot: (patch: Partial<DashboardFilters>, view?: View) => void;
}

interface AppContextValue {
  state: AppState;
  actions: AppActions;
  client: AnalysisClient;
  eventFilter: EventFilter;
  workerMode: 'worker' | 'in-process';
}

const AppContext = createContext<AppContextValue | null>(null);

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Unexpected error.';
}

export function AppProvider({
  children,
  workerFactory,
}: {
  children: ReactNode;
  workerFactory?: WorkerFactory;
}) {
  const [state, dispatch] = useReducer(reducer, undefined, initialState);
  // Latest state for async callbacks; updated after each commit, never read during render.
  const stateRef = useRef(state);
  useLayoutEffect(() => {
    stateRef.current = state;
  });

  const workerMode: AppContextValue['workerMode'] =
    workerFactory || supportsWorkers() ? 'worker' : 'in-process';
  const [client] = useState(
    () =>
      new AnalysisClient(
        workerFactory ?? (supportsWorkers() ? createAnalysisWorker : createLazyInProcessWorker),
      ),
  );

  useEffect(() => {
    // A crash or timeout after a scan means the worker (and its dataset) is gone.
    client.setCrashHandler((error) => {
      if (stateRef.current.scan.phase === 'ready')
        dispatch({ type: 'datasetLost', error: error.message });
    });
    return () => client.dispose();
  }, [client]);

  // The view is mirrored in the URL hash so the browser's back and forward buttons work
  // and a view can be linked. Views that need data fall back to the data source.
  useEffect(() => {
    const target = `#/${state.view}`;
    if (window.location.hash !== target) window.location.hash = target;
  }, [state.view]);
  useEffect(() => {
    const onHash = () => {
      const view = viewFromHash(window.location.hash);
      if (view && view !== stateRef.current.view) dispatch({ type: 'navigate', view });
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const startScan = useCallback(
    async (source: AnalyzeSource, parse: ParseOptions) => {
      const name = source.kind === 'sample' ? source.sampleId : source.name;
      dispatch({ type: 'scanStarted', sourceName: name });
      const s = stateRef.current;
      const timeZone = s.timeZone;
      try {
        const summary = await client.analyze(
          source,
          { parse, limits: s.limits, detection: s.detectionConfig, timeZone },
          (progress) => dispatch({ type: 'scanProgress', progress }),
        );
        dispatch({ type: 'scanSucceeded', summary, timeZone });
        return true;
      } catch (error) {
        if (error instanceof AnalysisCancelledError) dispatch({ type: 'scanCancelled' });
        else dispatch({ type: 'scanFailed', error: messageOf(error) });
        return false;
      }
    },
    [client],
  );

  // A link such as ?sample=ssh-auth#/alerts opens a synthetic sample directly (demos, the README).
  // Only bundled samples can be loaded this way: logs are never fetched from a URL.
  const autoStarted = useRef(false);
  // Read before any effect mirrors the initial view into the hash.
  const [initialHash] = useState(() => window.location.hash);
  useEffect(() => {
    if (autoStarted.current) return;
    autoStarted.current = true;
    const id = new URLSearchParams(window.location.search).get('sample');
    if (!isSampleId(id)) return;
    const wanted = viewFromHash(initialHash);
    const info = sampleInfo(id);
    void startScan(
      { kind: 'sample', sampleId: id },
      { format: info.format, timestamps: { assumedYear: SAMPLE_YEAR, sourceOffsetMinutes: 0 } },
    ).then((ok) => {
      if (ok && wanted) dispatch({ type: 'navigate', view: wanted });
    });
  }, [startScan, initialHash]);

  const actions = useMemo<AppActions>(
    () => ({
      dispatch,
      navigate: (view) => dispatch({ type: 'navigate', view }),
      startScan,
      cancelScan: () => client.cancel(),
      newScan: () => {
        // Terminating the worker releases the previous dataset's memory immediately.
        client.cancel();
        dispatch({ type: 'resetDataset' });
      },
      applyDetectionConfig: async (input) => {
        const config = validateDetectionConfig(input);
        if (stateRef.current.scan.phase !== 'ready') {
          dispatch({ type: 'setDetectionConfig', config });
          return;
        }
        const timeZone = stateRef.current.timeZone;
        dispatch({ type: 'redetectStarted' });
        try {
          const result = await client.query({ type: 'redetect', detection: config, timeZone });
          dispatch({ type: 'redetectSucceeded', result, config, timeZone });
        } catch (error) {
          // A new scan cancels in-flight work; that is not a re-run failure.
          if (error instanceof AnalysisCancelledError) return;
          dispatch({ type: 'redetectFailed', error: messageOf(error) });
        }
      },
      setFilters: (filters) => dispatch({ type: 'setFilters', filters }),
      toggleFilter: (key, value) =>
        dispatch({
          type: 'setFilters',
          filters: toggleFilterValue(stateRef.current.filters, key, value),
        }),
      pivot: (patch, view = 'events') => {
        // A pivot replaces the current filters, so its result is exactly what the button says.
        dispatch({ type: 'setFilters', filters: { ...clearFilters(), ...patch } });
        dispatch({ type: 'navigate', view });
      },
    }),
    [client, startScan],
  );

  const eventFilter = useMemo(
    () => toEventFilter(state.filters, state.detections, state.statuses, state.timeZone),
    [state.filters, state.detections, state.statuses, state.timeZone],
  );

  const value = useMemo(
    () => ({ state, actions, client, eventFilter, workerMode }),
    [state, actions, client, eventFilter, workerMode],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside <AppProvider>');
  return ctx;
}
