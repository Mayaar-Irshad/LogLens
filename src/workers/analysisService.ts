import { computeMetrics } from '../features/analytics/aggregate';
import { DetectionIndex } from '../features/analytics/detectionIndex';
import { detectionsInScope, filterEventIds } from '../features/analytics/filterEvents';
import {
  MAX_PAGE_SIZE,
  pageOf,
  relatedEvents,
  sortEventIds,
  toRow,
} from '../features/analytics/query';
import { computeLanes, type LaneKey } from '../features/analytics/lanes';
import { validateDetectionConfig } from '../features/detection/config/detectionConfig';
import { runDetections, type RuleRun } from '../features/detection/engine/runDetections';
import { assessEntities, assessPosture } from '../features/detection/risk/risk';
import { Ingestor } from '../features/log-ingestion/ingest';
import {
  LineSplitter,
  readBlobChunks,
  type LineItem,
} from '../features/log-ingestion/lineSplitter';
import { validateLimits } from '../features/log-ingestion/validation/limits';
import { validateParseOptions } from '../features/log-ingestion/validation/parseOptions';
import { eventsToCsv } from '../features/reporting/csv';
import {
  generateSample,
  isSampleId,
  SAMPLE_YEAR,
  sampleInfo,
} from '../features/sample-data/samples';
import type { DisplayTimeZone, EventFilter, EventSort } from '../types/analytics';
import type { Detection, DetectionSummary } from '../types/detection';
import type { NormalizedEvent } from '../types/events';
import type { IngestResult, ParseOptions, ResourceLimits } from '../types/ingestion';
import { formatBytes } from '../utils/format';
import { isRecord } from '../utils/validation';
import {
  DETECTION_SAMPLE_IDS,
  type AnalysisSummary,
  type AnalyzeSource,
  type Capabilities,
  type RedetectResult,
  type ResultMap,
  type ScanProgress,
  type WorkerErrorCode,
  type WorkerRequest,
  type WorkerResponse,
} from './protocol';

export class ServiceError extends Error {
  constructor(
    readonly code: WorkerErrorCode,
    message: string,
  ) {
    super(message);
  }
}

interface Dataset {
  ingest: IngestResult;
  events: NormalizedEvent[];
  detections: Detection[];
  ruleRuns: RuleRun[];
  index: DetectionIndex;
}

const PROGRESS_INTERVAL_MS = 150;
const TEXT_SLICE = 1 << 20;
const TIME_ZONES: readonly DisplayTimeZone[] = ['UTC', 'local'];

export function summarizeDetection(d: Detection): DetectionSummary {
  return {
    ...d,
    eventIds: d.eventIds.slice(0, DETECTION_SAMPLE_IDS),
    eventIdsSampled: d.eventIds.length > DETECTION_SAMPLE_IDS,
  };
}

function capabilities(events: readonly NormalizedEvent[]): Capabilities {
  const caps: Capabilities = {
    hasAuth: false,
    hasWeb: false,
    hasTimestamps: false,
    hasIps: false,
    hasUsers: false,
  };
  for (const e of events) {
    if (e.category === 'authentication' && e.auth?.outcome) caps.hasAuth = true;
    if (e.http) caps.hasWeb = true;
    if (e.timestamp !== undefined) caps.hasTimestamps = true;
    if (e.sourceIp) caps.hasIps = true;
    if (e.username) caps.hasUsers = true;
    if (caps.hasAuth && caps.hasWeb && caps.hasTimestamps && caps.hasIps && caps.hasUsers) break;
  }
  return caps;
}

const tzOf = (value: unknown): DisplayTimeZone =>
  TIME_ZONES.includes(value as DisplayTimeZone) ? (value as DisplayTimeZone) : 'UTC';

/** Accept only the filter keys the engine knows; everything else is ignored. */
function sanitizeFilter(input: unknown): EventFilter {
  if (!isRecord(input)) return {};
  const strings = (v: unknown, max = 500): string[] | undefined =>
    Array.isArray(v)
      ? v.filter((x): x is string => typeof x === 'string').slice(0, max)
      : undefined;
  const numbers = (v: unknown): number[] | undefined =>
    Array.isArray(v)
      ? v.filter((x): x is number => typeof x === 'number' && Number.isFinite(x)).slice(0, 500)
      : undefined;
  const out: EventFilter = { timeZone: tzOf(input.timeZone) };
  if (isRecord(input.timeRange)) {
    const { start, end } = input.timeRange;
    out.timeRange = {
      ...(typeof start === 'number' && Number.isFinite(start) ? { start } : {}),
      ...(typeof end === 'number' && Number.isFinite(end) ? { end } : {}),
    };
  }
  const assign = <K extends keyof EventFilter>(key: K, value: EventFilter[K] | undefined): void => {
    if (value !== undefined) out[key] = value;
  };
  assign('sourceIps', strings(input.sourceIps));
  assign('usernames', strings(input.usernames));
  assign('categories', strings(input.categories) as EventFilter['categories']);
  assign('actions', strings(input.actions));
  assign('authOutcomes', strings(input.authOutcomes) as EventFilter['authOutcomes']);
  assign('httpMethods', strings(input.httpMethods));
  assign('httpStatuses', numbers(input.httpStatuses));
  assign('statusClasses', strings(input.statusClasses) as EventFilter['statusClasses']);
  assign('paths', strings(input.paths));
  assign('hours', numbers(input.hours));
  assign('parseStatuses', strings(input.parseStatuses) as EventFilter['parseStatuses']);
  assign('formats', strings(input.formats) as EventFilter['formats']);
  if (input.detectionIds !== null && input.detectionIds !== undefined) {
    assign('detectionIds', strings(input.detectionIds, 5000) ?? []);
  }
  if (typeof input.search === 'string') out.search = input.search.slice(0, 200);
  return out;
}

const SORT_FIELDS = ['timestamp', 'line', 'sourceIp', 'username', 'action', 'status'] as const;
function sanitizeSort(input: unknown): EventSort {
  const src = isRecord(input) ? input : {};
  const field = SORT_FIELDS.includes(src.field as (typeof SORT_FIELDS)[number])
    ? (src.field as EventSort['field'])
    : 'timestamp';
  return { field, direction: src.direction === 'desc' ? 'desc' : 'asc' };
}

/**
 * Owns the parsed dataset inside the worker and answers queries about it.
 * Contains no DOM or worker APIs, so it is unit-testable and can also run
 * in-process when Web Workers are unavailable.
 */
export class AnalysisService {
  private dataset: Dataset | null = null;
  private filterCache: { key: string; ids: number[] } | null = null;
  private sortCache: { key: string; ids: number[] } | null = null;

  constructor(private readonly clock: () => number = () => Date.now()) {}

  get hasDataset(): boolean {
    return this.dataset !== null;
  }

  async handle(request: WorkerRequest, post: (response: WorkerResponse) => void): Promise<void> {
    const id = typeof request?.id === 'number' ? request.id : -1;
    try {
      const result = await this.dispatch(request, (progress) =>
        post({ id, type: 'progress', progress }),
      );
      post({ id, type: 'result', result });
    } catch (error) {
      const code: WorkerErrorCode = error instanceof ServiceError ? error.code : 'internal';
      const message =
        error instanceof ServiceError
          ? error.message
          : `Analysis failed unexpectedly${error instanceof Error ? ` (${error.name})` : ''}.`;
      post({ id, type: 'error', error: { code, message } });
    }
  }

  private requireDataset(): Dataset {
    if (!this.dataset)
      throw new ServiceError('no_dataset', 'No dataset is loaded. Run a scan first.');
    return this.dataset;
  }

  private filtered(filter: EventFilter): number[] {
    const ds = this.requireDataset();
    const key = JSON.stringify(filter);
    if (this.filterCache?.key === key) return this.filterCache.ids;
    const ids = filterEventIds(ds.events, filter, ds.index);
    this.filterCache = { key, ids };
    this.sortCache = null;
    return ids;
  }

  private async dispatch(
    request: WorkerRequest,
    onProgress: (p: ScanProgress) => void,
  ): Promise<ResultMap[WorkerRequest['type']]> {
    if (!isRecord(request) || typeof request.type !== 'string') {
      throw new ServiceError('invalid_request', 'Malformed request.');
    }
    switch (request.type) {
      case 'analyze':
        return this.analyze(request.source, request.options, onProgress);
      case 'redetect':
        return this.redetect(request.detection, tzOf(request.timeZone));
      case 'metrics': {
        const ds = this.requireDataset();
        const filter = sanitizeFilter(request.filter);
        const ids = this.filtered(filter);
        return {
          metrics: computeMetrics(ds.events, ids, {
            timeZone: filter.timeZone ?? 'UTC',
            index: ds.index,
          }),
          detectionIdsInScope: detectionsInScope(ids, filter, ds.index),
          matchingEvents: ids.length,
        };
      }
      case 'events': {
        const ds = this.requireDataset();
        const filter = sanitizeFilter(request.filter);
        const sort = sanitizeSort(request.sort);
        const ids = this.filtered(filter);
        const key = `${JSON.stringify(filter)}|${sort.field}|${sort.direction}`;
        if (this.sortCache?.key !== key)
          this.sortCache = { key, ids: sortEventIds(ds.events, ids, sort) };
        return pageOf(ds.events, this.sortCache.ids, request.page, request.pageSize, ds.index);
      }
      case 'eventsById': {
        const ds = this.requireDataset();
        const ids = Array.isArray(request.ids) ? request.ids.slice(0, MAX_PAGE_SIZE) : [];
        return ids
          .filter((i) => Number.isInteger(i) && i >= 0 && i < ds.events.length)
          .map((i) => toRow(ds.events[i]!, ds.index));
      }
      case 'detectionEvents': {
        const ds = this.requireDataset();
        const detection = ds.index.get(String(request.detectionId));
        if (!detection) throw new ServiceError('invalid_request', 'Unknown detection.');
        const sorted = sortEventIds(ds.events, detection.eventIds, {
          field: 'timestamp',
          direction: 'asc',
        });
        return pageOf(ds.events, sorted, request.page, request.pageSize, ds.index);
      }
      case 'related': {
        const ds = this.requireDataset();
        const by = request.by === 'user' || request.by === 'window' ? request.by : 'ip';
        const limit = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(Number(request.limit)) || 50));
        return relatedEvents(
          ds.events,
          Math.floor(Number(request.eventId)),
          by,
          Number(request.windowMinutes) || 5,
          limit,
          ds.index,
        );
      }
      case 'exportEvents': {
        const ds = this.requireDataset();
        const ids = this.filtered(sanitizeFilter(request.filter));
        return eventsToCsv(ds.events, ids, {
          includeRaw: request.includeRaw === true,
          timeZone: tzOf(request.timeZone),
          index: ds.index,
        });
      }
      case 'lanes': {
        const ds = this.requireDataset();
        const keys: LaneKey[] = (Array.isArray(request.keys) ? request.keys : [])
          .filter(
            (k): k is LaneKey =>
              isRecord(k) && (k.kind === 'ip' || k.kind === 'user') && typeof k.value === 'string',
          )
          .map((k) => ({ kind: k.kind, value: k.value }));
        const ids = this.filtered(sanitizeFilter(request.filter));
        return computeLanes(ds.events, ids, keys, Number(request.cells));
      }
      case 'reset':
        this.reset();
        return { ok: true };
      default:
        throw new ServiceError('invalid_request', 'Unknown request type.');
    }
  }

  reset(): void {
    this.dataset = null;
    this.filterCache = null;
    this.sortCache = null;
  }

  private async analyze(
    sourceInput: AnalyzeSource,
    optionsInput: unknown,
    onProgress: (p: ScanProgress) => void,
  ): Promise<AnalysisSummary> {
    // A new scan always discards the previous dataset first.
    this.reset();
    const started = this.clock();
    const opts = isRecord(optionsInput) ? optionsInput : {};
    const limits: ResourceLimits = validateLimits(opts.limits);
    let parseOptions: ParseOptions = validateParseOptions(opts.parse);
    const detectionConfig = validateDetectionConfig(opts.detection);
    const timeZone = tzOf(opts.timeZone);
    const splitter = new LineSplitter(limits.maxLineLength);

    let name: string;
    let sizeBytes = 0;
    let read: (
      ingestor: Ingestor,
      feed: (items: LineItem[]) => void,
      report: (bytes: number) => void,
    ) => Promise<void>;

    if (!isRecord(sourceInput)) throw new ServiceError('invalid_request', 'Missing input source.');
    if (sourceInput.kind === 'file') {
      const file = sourceInput.file;
      if (!(file instanceof Blob))
        throw new ServiceError('invalid_request', 'The selected file could not be read.');
      name = String(sourceInput.name ?? 'file');
      sizeBytes = file.size;
      read = async (_ingestor, feed, report) => {
        for await (const chunk of readBlobChunks(file)) {
          feed(splitter.push(chunk.text));
          report(chunk.bytes);
        }
      };
    } else if (sourceInput.kind === 'text' || sourceInput.kind === 'sample') {
      let text: string;
      if (sourceInput.kind === 'sample') {
        if (!isSampleId(sourceInput.sampleId))
          throw new ServiceError('invalid_request', 'Unknown sample dataset.');
        const info = sampleInfo(sourceInput.sampleId);
        text = generateSample(sourceInput.sampleId);
        name = info.fileName;
        parseOptions = {
          format: info.format,
          timestamps: { assumedYear: SAMPLE_YEAR, sourceOffsetMinutes: 0 },
          ...(info.mapping ? { mapping: info.mapping } : {}),
        };
      } else {
        text = typeof sourceInput.text === 'string' ? sourceInput.text : '';
        name = String(sourceInput.name ?? 'pasted text');
      }
      const encoded = new TextEncoder().encode(text).byteLength;
      sizeBytes = encoded;
      read = async (_ingestor, feed, report) => {
        for (let i = 0; i < text.length; i += TEXT_SLICE) {
          const slice = text.slice(i, i + TEXT_SLICE);
          feed(splitter.push(i === 0 ? slice.replace(/^\ufeff/, '') : slice));
          report(Math.round((slice.length / text.length) * encoded));
          await Promise.resolve();
        }
      };
    } else {
      throw new ServiceError('invalid_request', 'Unsupported input source.');
    }
    if (sizeBytes > limits.maxFileSizeBytes) {
      throw new ServiceError(
        'input_too_large',
        `Input is ${formatBytes(sizeBytes)}, above the ${formatBytes(limits.maxFileSizeBytes)} limit.`,
      );
    }

    const ingestor = new Ingestor({ parse: parseOptions, limits, now: this.clock() });
    let bytes = 0;
    let lastReport = 0;
    const progress = (phase: ScanProgress['phase']): ScanProgress => ({
      phase,
      bytesProcessed: bytes,
      totalBytes: sizeBytes,
      linesProcessed: ingestor.lines,
      eventsCreated: ingestor.eventCount,
    });
    const feed = (items: LineItem[]): void => {
      for (const item of items) {
        if (item.kind === 'line') ingestor.pushLine(item.text);
        else ingestor.pushOverlong(item.preview, item.length);
      }
    };
    const report = (n: number): void => {
      bytes = Math.min(sizeBytes, bytes + n);
      ingestor.addBytes(n);
      const now = this.clock();
      if (now - lastReport >= PROGRESS_INTERVAL_MS) {
        lastReport = now;
        onProgress(progress('reading'));
      }
    };
    onProgress(progress('reading'));
    await read(ingestor, feed, report);
    feed(splitter.finish());
    const ingest = ingestor.finish();
    const parsedAt = this.clock();

    onProgress(progress('detecting'));
    const run = runDetections(ingest.events, detectionConfig, { stats: ingest.stats });
    onProgress(progress('indexing'));
    const index = new DetectionIndex(run.detections);
    this.dataset = {
      ingest,
      events: ingest.events,
      detections: run.detections,
      ruleRuns: run.ruleRuns,
      index,
    };
    const metrics = computeMetrics(ingest.events, null, { timeZone, index });
    const finished = this.clock();
    onProgress({ ...progress('done'), bytesProcessed: sizeBytes });

    return {
      source: { name: name.slice(0, 255), kind: sourceInput.kind, sizeBytes },
      format: ingest.format,
      parseOptions,
      limits,
      stats: ingest.stats,
      rejected: ingest.rejected,
      limitReached: ingest.limitReached,
      detections: run.detections.map(summarizeDetection),
      ruleRuns: run.ruleRuns,
      entities: assessEntities(run.detections).slice(0, 50),
      posture: assessPosture(run.detections),
      metrics,
      capabilities: capabilities(ingest.events),
      timing: {
        parseMs: parsedAt - started,
        detectMs: finished - parsedAt,
        totalMs: finished - started,
      },
      completedAt: finished,
    };
  }

  private redetect(configInput: unknown, timeZone: DisplayTimeZone): RedetectResult {
    const ds = this.requireDataset();
    const run = runDetections(ds.events, validateDetectionConfig(configInput), {
      stats: ds.ingest.stats,
    });
    ds.detections = run.detections;
    ds.ruleRuns = run.ruleRuns;
    ds.index = new DetectionIndex(run.detections);
    this.filterCache = null;
    this.sortCache = null;
    return {
      detections: run.detections.map(summarizeDetection),
      ruleRuns: run.ruleRuns,
      entities: assessEntities(run.detections).slice(0, 50),
      posture: assessPosture(run.detections),
      metrics: computeMetrics(ds.events, null, { timeZone, index: ds.index }),
      durationMs: run.durationMs,
    };
  }
}
