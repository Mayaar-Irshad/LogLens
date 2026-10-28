import {
  EMPTY_FILTERS,
  type DashboardFilters,
  type DisplayTimeZone,
  type EventFilter,
} from '../../types/analytics';
import type { AlertStatus, DetectionSummary } from '../../types/detection';

/**
 * Translation between the analyst-facing filter state and the queries the
 * worker evaluates. Keeping this pure guarantees that charts, counters, alert
 * lists and the event table all derive from the same definition.
 */

export type ArrayFilterKey = {
  [K in keyof DashboardFilters]: DashboardFilters[K] extends unknown[] ? K : never;
}[keyof DashboardFilters];

export const statusOf = (
  statuses: Readonly<Record<string, AlertStatus>>,
  id: string,
): AlertStatus => (Object.prototype.hasOwnProperty.call(statuses, id) ? statuses[id]! : 'open');

export function hasAlertAttributeFilters(f: DashboardFilters): boolean {
  return f.severities.length > 0 || f.ruleIds.length > 0 || f.alertStatuses.length > 0;
}

export function hasEventAttributeFilters(f: DashboardFilters): boolean {
  return (
    f.timeRange.start !== undefined ||
    f.timeRange.end !== undefined ||
    f.sourceIps.length > 0 ||
    f.usernames.length > 0 ||
    f.categories.length > 0 ||
    f.actions.length > 0 ||
    f.authOutcomes.length > 0 ||
    f.httpMethods.length > 0 ||
    f.httpStatuses.length > 0 ||
    f.statusClasses.length > 0 ||
    f.paths.length > 0 ||
    f.hours.length > 0 ||
    f.search.trim() !== ''
  );
}

export function hasActiveFilters(f: DashboardFilters): boolean {
  return hasEventAttributeFilters(f) || hasAlertAttributeFilters(f);
}

export function matchesAlertAttributes(
  d: DetectionSummary,
  f: DashboardFilters,
  statuses: Readonly<Record<string, AlertStatus>>,
): boolean {
  if (f.severities.length > 0 && !f.severities.includes(d.severity)) return false;
  if (f.ruleIds.length > 0 && !f.ruleIds.includes(d.ruleId)) return false;
  if (f.alertStatuses.length > 0 && !f.alertStatuses.includes(statusOf(statuses, d.id)))
    return false;
  return true;
}

/** Build the worker-side event filter. Alert-attribute filters become a detection-id constraint. */
export function toEventFilter(
  f: DashboardFilters,
  detections: readonly DetectionSummary[],
  statuses: Readonly<Record<string, AlertStatus>>,
  timeZone: DisplayTimeZone,
): EventFilter {
  const out: EventFilter = { timeZone };
  if (f.timeRange.start !== undefined || f.timeRange.end !== undefined)
    out.timeRange = { ...f.timeRange };
  if (f.sourceIps.length) out.sourceIps = f.sourceIps;
  if (f.usernames.length) out.usernames = f.usernames;
  if (f.categories.length) out.categories = f.categories;
  if (f.actions.length) out.actions = f.actions;
  if (f.authOutcomes.length) out.authOutcomes = f.authOutcomes;
  if (f.httpMethods.length) out.httpMethods = f.httpMethods;
  if (f.httpStatuses.length) out.httpStatuses = f.httpStatuses;
  if (f.statusClasses.length) out.statusClasses = f.statusClasses;
  if (f.paths.length) out.paths = f.paths;
  if (f.hours.length) out.hours = f.hours;
  if (f.search.trim()) out.search = f.search.trim();
  if (hasAlertAttributeFilters(f)) {
    out.detectionIds = detections
      .filter((d) => matchesAlertAttributes(d, f, statuses))
      .map((d) => d.id);
  }
  return out;
}

/**
 * Detections visible under the current filters: matching alert attributes and,
 * when event filters are active, supported by at least one matching event.
 */
export function filterDetections(
  detections: readonly DetectionSummary[],
  f: DashboardFilters,
  statuses: Readonly<Record<string, AlertStatus>>,
  inScope: readonly string[] | null,
): DetectionSummary[] {
  const scope = inScope && hasEventAttributeFilters(f) ? new Set(inScope) : null;
  return detections.filter(
    (d) => matchesAlertAttributes(d, f, statuses) && (!scope || scope.has(d.id)),
  );
}

/** Toggle one value inside an array filter. */
export function toggleFilterValue<K extends ArrayFilterKey>(
  f: DashboardFilters,
  key: K,
  value: DashboardFilters[K][number],
): DashboardFilters {
  const list = f[key] as unknown[];
  const next = list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
  return { ...f, [key]: next };
}

export interface FilterChip {
  key: keyof DashboardFilters;
  value: string | number;
  label: string;
}

const LABELS: Partial<Record<keyof DashboardFilters, string>> = {
  sourceIps: 'IP',
  usernames: 'User',
  categories: 'Category',
  actions: 'Action',
  authOutcomes: 'Outcome',
  httpMethods: 'Method',
  httpStatuses: 'Status',
  statusClasses: 'Status class',
  paths: 'Path',
  hours: 'Hour',
  severities: 'Severity',
  ruleIds: 'Rule',
  alertStatuses: 'Alert status',
};

export function filterChips(f: DashboardFilters, timeZone: DisplayTimeZone = 'UTC'): FilterChip[] {
  const chips: FilterChip[] = [];
  for (const key of Object.keys(LABELS) as ArrayFilterKey[]) {
    for (const value of f[key] as Array<string | number>) {
      const shown =
        key === 'hours'
          ? `${String(value).padStart(2, '0')}:00 ${timeZone === 'UTC' ? 'UTC' : 'local'}`
          : String(value);
      chips.push({ key, value, label: `${LABELS[key]}: ${shown}` });
    }
  }
  if (f.search.trim())
    chips.push({ key: 'search', value: f.search, label: `Search: ${f.search.trim()}` });
  return chips;
}

export function removeChip(f: DashboardFilters, chip: FilterChip): DashboardFilters {
  if (chip.key === 'search') return { ...f, search: '' };
  if (chip.key === 'timeRange') return { ...f, timeRange: {} };
  const list = f[chip.key] as Array<string | number>;
  return { ...f, [chip.key]: list.filter((v) => v !== chip.value) };
}

export function clearFilters(): DashboardFilters {
  return { ...EMPTY_FILTERS, timeRange: {} };
}
