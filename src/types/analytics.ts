import type { AuthOutcome, EventCategory, LogFormat, NormalizedEvent, ParseStatus } from './events';
import type { AlertStatus, RuleId, Severity } from './detection';

export type DisplayTimeZone = 'UTC' | 'local';

export interface TimeRange {
  start?: number;
  end?: number;
}

export type StatusClass = '1xx' | '2xx' | '3xx' | '4xx' | '5xx';

/**
 * Filters chosen by the analyst. Event-attribute filters constrain events
 * directly; alert-attribute filters (severity, rule, status) constrain events to
 * those that support a matching alert. Every view derives its data from the
 * same filter state.
 */
export interface DashboardFilters {
  timeRange: TimeRange;
  sourceIps: string[];
  usernames: string[];
  categories: EventCategory[];
  actions: string[];
  authOutcomes: AuthOutcome[];
  httpMethods: string[];
  httpStatuses: number[];
  statusClasses: StatusClass[];
  paths: string[];
  hours: number[];
  severities: Severity[];
  ruleIds: RuleId[];
  alertStatuses: AlertStatus[];
  search: string;
}

export const EMPTY_FILTERS: DashboardFilters = {
  timeRange: {},
  sourceIps: [],
  usernames: [],
  categories: [],
  actions: [],
  authOutcomes: [],
  httpMethods: [],
  httpStatuses: [],
  statusClasses: [],
  paths: [],
  hours: [],
  severities: [],
  ruleIds: [],
  alertStatuses: [],
  search: '',
};

/** The event-level filter evaluated inside the worker. */
export interface EventFilter {
  timeRange?: TimeRange;
  sourceIps?: string[];
  usernames?: string[];
  categories?: EventCategory[];
  actions?: string[];
  authOutcomes?: AuthOutcome[];
  httpMethods?: string[];
  httpStatuses?: number[];
  statusClasses?: StatusClass[];
  paths?: string[];
  hours?: number[];
  parseStatuses?: ParseStatus[];
  formats?: LogFormat[];
  /** When set, only events supporting at least one of these detections match. */
  detectionIds?: string[];
  search?: string;
  /** Time zone used to interpret `hours`. */
  timeZone?: DisplayTimeZone;
}

export interface CountItem {
  key: string;
  count: number;
}

export interface TimeBucket {
  /** Bucket start, epoch ms. */
  t: number;
  total: number;
  authSuccess: number;
  authFailure: number;
  web2xx: number;
  web3xx: number;
  web4xx: number;
  web5xx: number;
  other: number;
}

export interface DashboardMetrics {
  totalEvents: number;
  timedEvents: number;
  timeRange: TimeRange;
  uniqueIps: number;
  uniqueUsers: number;
  categories: CountItem[];
  formats: CountItem[];
  auth: {
    total: number;
    success: number;
    failure: number;
    invalidUserAttempts: number;
    topFailedUsers: CountItem[];
    topFailedIps: CountItem[];
    topSuccessUsers: CountItem[];
  };
  web: {
    total: number;
    statusCodes: CountItem[];
    statusClasses: CountItem[];
    methods: CountItem[];
    topPaths: CountItem[];
    topErrorPaths: CountItem[];
    topClients: CountItem[];
    topUserAgents: CountItem[];
    uniqueClients: number;
    uniquePaths: number;
    bytes: number;
  };
  topIps: CountItem[];
  topUsers: CountItem[];
  /** Hour-of-day histogram (24 entries) in the requested time zone. */
  hourly: Array<{
    hour: number;
    total: number;
    authFailure: number;
    authSuccess: number;
    web: number;
  }>;
  timeline: { bucketMs: number; buckets: TimeBucket[] };
  partialEvents: number;
  flaggedEvents: number;
  severityByEvent: CountItem[];
}

export type SortField = 'timestamp' | 'line' | 'sourceIp' | 'username' | 'action' | 'status';

export interface EventSort {
  field: SortField;
  direction: 'asc' | 'desc';
}

/** An event row as shown in tables, with derived alert context. */
export interface EventRow extends NormalizedEvent {
  maxSeverity?: Severity;
  detectionIds: string[];
}

export interface EventPage {
  rows: EventRow[];
  total: number;
  page: number;
  pageSize: number;
}

export type RelatedBy = 'ip' | 'user' | 'window';
