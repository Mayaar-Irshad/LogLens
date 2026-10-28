import { defaultDetectionConfig } from '../features/detection/config/detectionConfig';
import type { RuleRun } from '../features/detection/engine/runDetections';
import type { Posture } from '../features/detection/risk/risk';
import { clearFilters } from '../features/investigation/filters';
import { DEFAULT_LIMITS } from '../features/log-ingestion/validation/limits';
import type { DashboardFilters, DashboardMetrics, DisplayTimeZone } from '../types/analytics';
import type {
  AlertStatus,
  DetectionConfig,
  DetectionSummary,
  EntityRisk,
} from '../types/detection';
import type { ResourceLimits } from '../types/ingestion';
import type { AnalysisSummary, RedetectResult, ScanProgress } from '../workers/protocol';

export type View = 'data' | 'overview' | 'auth' | 'web' | 'alerts' | 'events' | 'rules' | 'report';

export const VIEWS: readonly View[] = [
  'data',
  'overview',
  'auth',
  'web',
  'alerts',
  'events',
  'rules',
  'report',
];

/** Views that need a loaded dataset; without one they fall back to the data source. */
export const DATA_VIEWS: readonly View[] = [
  'overview',
  'auth',
  'web',
  'alerts',
  'events',
  'report',
];

export interface RedetectSummary {
  before: number;
  after: number;
  added: number;
  removed: number;
}

export type ScanPhase = 'idle' | 'scanning' | 'ready' | 'error';

export interface AppState {
  view: View;
  scan: {
    phase: ScanPhase;
    sourceName?: string;
    progress?: ScanProgress;
    error?: string;
    notice?: string;
  };
  summary: AnalysisSummary | null;
  detections: DetectionSummary[];
  ruleRuns: RuleRun[];
  entities: EntityRisk[];
  posture: Posture | null;
  /** Unfiltered metrics for the current dataset. */
  baseMetrics: DashboardMetrics | null;
  /** Time zone the base metrics were computed in. */
  baseMetricsTimeZone: DisplayTimeZone;
  filters: DashboardFilters;
  timeZone: DisplayTimeZone;
  /** Investigation state lives in memory only and is cleared on every new scan. */
  statuses: Record<string, AlertStatus>;
  notes: Record<string, string>;
  caseNote: string;
  detectionConfig: DetectionConfig;
  limits: ResourceLimits;
  selectedDetectionId: string | null;
  selectedEventId: number | null;
  redetecting: boolean;
  redetectError: string | null;
  lastRedetect: RedetectSummary | null;
  /** Bumped whenever the set of detections is replaced; part of every query key. */
  detectionsVersion: number;
}

export type Action =
  | { type: 'navigate'; view: View }
  | { type: 'scanStarted'; sourceName: string }
  | { type: 'scanProgress'; progress: ScanProgress }
  | { type: 'scanSucceeded'; summary: AnalysisSummary; timeZone: DisplayTimeZone }
  | { type: 'scanFailed'; error: string }
  | { type: 'scanCancelled' }
  | { type: 'datasetLost'; error: string }
  | { type: 'resetDataset' }
  | { type: 'setFilters'; filters: DashboardFilters }
  | { type: 'setTimeZone'; timeZone: DisplayTimeZone }
  | { type: 'setStatus'; id: string; status: AlertStatus }
  | { type: 'setNote'; id: string; note: string }
  | { type: 'setCaseNote'; note: string }
  | { type: 'setDetectionConfig'; config: DetectionConfig }
  | { type: 'redetectStarted' }
  | {
      type: 'redetectSucceeded';
      result: RedetectResult;
      config: DetectionConfig;
      timeZone: DisplayTimeZone;
    }
  | { type: 'redetectFailed'; error: string }
  | { type: 'setLimits'; limits: ResourceLimits }
  | { type: 'selectDetection'; id: string | null }
  | { type: 'selectEvent'; id: number | null };

export function initialState(): AppState {
  return {
    view: 'data',
    scan: { phase: 'idle' },
    summary: null,
    detections: [],
    ruleRuns: [],
    entities: [],
    posture: null,
    baseMetrics: null,
    baseMetricsTimeZone: 'UTC',
    filters: clearFilters(),
    timeZone: 'UTC',
    statuses: {},
    notes: {},
    caseNote: '',
    detectionConfig: defaultDetectionConfig(),
    limits: { ...DEFAULT_LIMITS },
    selectedDetectionId: null,
    selectedEventId: null,
    redetecting: false,
    redetectError: null,
    lastRedetect: null,
    detectionsVersion: 0,
  };
}

/** Everything tied to a dataset. Cleared whenever a different input is loaded. */
function clearDataset(state: AppState): AppState {
  return {
    ...state,
    summary: null,
    detections: [],
    ruleRuns: [],
    entities: [],
    posture: null,
    baseMetrics: null,
    filters: clearFilters(),
    statuses: {},
    notes: {},
    caseNote: '',
    selectedDetectionId: null,
    selectedEventId: null,
    redetecting: false,
    redetectError: null,
    lastRedetect: null,
    detectionsVersion: state.detectionsVersion + 1,
  };
}

const keep = <T>(record: Record<string, T>, ids: Set<string>): Record<string, T> => {
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(record)) if (ids.has(k)) out[k] = v;
  return out;
};

export function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'navigate':
      return {
        ...state,
        view: DATA_VIEWS.includes(action.view) && !state.summary ? 'data' : action.view,
      };
    case 'scanStarted':
      return {
        ...clearDataset(state),
        view: 'data',
        scan: { phase: 'scanning', sourceName: action.sourceName },
      };
    case 'scanProgress':
      return state.scan.phase === 'scanning'
        ? { ...state, scan: { ...state.scan, progress: action.progress } }
        : state;
    case 'scanSucceeded':
      return {
        ...state,
        scan: { phase: 'ready', sourceName: action.summary.source.name },
        summary: action.summary,
        detections: action.summary.detections,
        ruleRuns: action.summary.ruleRuns,
        entities: action.summary.entities,
        posture: action.summary.posture,
        baseMetrics: action.summary.metrics,
        // The zone the worker computed with, not the zone selected when the answer arrived.
        baseMetricsTimeZone: action.timeZone,
        detectionsVersion: state.detectionsVersion + 1,
        view: 'overview',
      };
    case 'scanFailed':
      return {
        ...clearDataset(state),
        view: 'data',
        scan: { phase: 'error', error: action.error },
      };
    case 'scanCancelled':
      return {
        ...clearDataset(state),
        view: 'data',
        scan: { phase: 'idle', notice: 'The scan was cancelled. No data was kept.' },
      };
    case 'datasetLost':
      return {
        ...clearDataset(state),
        view: 'data',
        scan: { phase: 'error', error: action.error },
      };
    case 'resetDataset':
      return { ...clearDataset(state), view: 'data', scan: { phase: 'idle' } };
    case 'setFilters':
      return { ...state, filters: action.filters };
    case 'setTimeZone':
      return { ...state, timeZone: action.timeZone };
    case 'setStatus':
      return { ...state, statuses: { ...state.statuses, [action.id]: action.status } };
    case 'setNote':
      return { ...state, notes: { ...state.notes, [action.id]: action.note.slice(0, 10_000) } };
    case 'setCaseNote':
      return { ...state, caseNote: action.note.slice(0, 50_000) };
    case 'setDetectionConfig':
      return { ...state, detectionConfig: action.config };
    case 'redetectStarted':
      return { ...state, redetecting: true, redetectError: null };
    case 'redetectSucceeded': {
      const ids = new Set(action.result.detections.map((d) => d.id));
      const previous = new Set(state.detections.map((d) => d.id));
      return {
        ...state,
        redetecting: false,
        redetectError: null,
        // The configuration is committed only once detections were actually re-run with it.
        detectionConfig: action.config,
        detectionsVersion: state.detectionsVersion + 1,
        lastRedetect: {
          before: previous.size,
          after: ids.size,
          added: [...ids].filter((id) => !previous.has(id)).length,
          removed: [...previous].filter((id) => !ids.has(id)).length,
        },
        detections: action.result.detections,
        ruleRuns: action.result.ruleRuns,
        entities: action.result.entities,
        posture: action.result.posture,
        baseMetrics: action.result.metrics,
        baseMetricsTimeZone: action.timeZone,
        // Detection ids are deterministic, so review state survives a re-run for unchanged findings.
        statuses: keep(state.statuses, ids),
        notes: keep(state.notes, ids),
        selectedDetectionId:
          state.selectedDetectionId && ids.has(state.selectedDetectionId)
            ? state.selectedDetectionId
            : null,
      };
    }
    case 'redetectFailed':
      return { ...state, redetecting: false, redetectError: action.error };
    case 'setLimits':
      return { ...state, limits: action.limits };
    case 'selectDetection':
      return { ...state, selectedDetectionId: action.id };
    case 'selectEvent':
      return { ...state, selectedEventId: action.id };
  }
}
