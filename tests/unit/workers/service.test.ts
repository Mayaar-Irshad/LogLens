import { describe, expect, it } from 'vitest';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { DEFAULT_LIMITS, MB } from '../../../src/features/log-ingestion/validation/limits';
import { validateParseOptions } from '../../../src/features/log-ingestion/validation/parseOptions';
import { AnalysisService } from '../../../src/workers/analysisService';
import type {
  AnalyzeOptions,
  AnalyzeSource,
  ResultMap,
  WorkerRequest,
  WorkerResponse,
} from '../../../src/workers/protocol';
import { fixture } from '../../helpers/ingest';

const options = (overrides: Partial<AnalyzeOptions> = {}): AnalyzeOptions => ({
  parse: { format: 'linux-auth', timestamps: { assumedYear: 2026, sourceOffsetMinutes: 0 } },
  limits: DEFAULT_LIMITS,
  detection: defaultDetectionConfig(),
  timeZone: 'UTC',
  ...overrides,
});

async function call<T>(
  service: AnalysisService,
  request: WorkerRequest,
): Promise<{ result?: T; error?: { code: string; message: string }; progress: WorkerResponse[] }> {
  const responses: WorkerResponse[] = [];
  await service.handle(request, (r) => responses.push(r));
  const final = responses[responses.length - 1]!;
  return {
    ...(final.type === 'result' ? { result: final.result as T } : {}),
    ...(final.type === 'error' ? { error: final.error } : {}),
    progress: responses.filter((r) => r.type === 'progress'),
  };
}

const analyze = (service: AnalysisService, source: AnalyzeSource, opts = options()) =>
  call<ResultMap['analyze']>(service, { id: 1, type: 'analyze', source, options: opts });

const BRUTE = Array.from(
  { length: 12 },
  (_, i) =>
    `Oct 27 10:00:${String(i).padStart(2, '0')} h sshd[1]: Failed password for root from 203.0.113.50 port ${2000 + i} ssh2`,
).join('\n');

describe('AnalysisService', () => {
  it('analyzes pasted text and reports progress phases', async () => {
    const service = new AnalysisService();
    const { result, progress } = await analyze(service, {
      kind: 'text',
      text: BRUTE,
      name: 'paste',
    });
    expect(result?.stats.eventsCreated).toBe(12);
    expect(result?.detections.map((d) => d.ruleId)).toContain('AUTH-001');
    expect(result?.capabilities).toMatchObject({
      hasAuth: true,
      hasWeb: false,
      hasTimestamps: true,
    });
    expect(
      progress
        .map((p) => (p.type === 'progress' ? p.progress.phase : ''))
        .filter((v, i, a) => a.indexOf(v) === i),
    ).toEqual(['reading', 'detecting', 'indexing', 'done']);
    expect(service.hasDataset).toBe(true);
  });

  it('streams files through the same pipeline', async () => {
    const service = new AnalysisService();
    const file = new Blob([fixture('web/access-combined.log')]);
    const { result } = await analyze(
      service,
      { kind: 'file', file, name: 'access.log' },
      options({
        parse: { format: 'nginx', timestamps: { assumedYear: 2026, sourceOffsetMinutes: 0 } },
      }),
    );
    expect(result?.format).toBe('nginx');
    expect(result?.stats).toMatchObject({
      totalLines: 12,
      rejectedRecords: 1,
      bytesRead: file.size,
    });
    expect(result?.source).toEqual({ name: 'access.log', kind: 'file', sizeBytes: file.size });
  });

  it('generates and analyzes sample datasets with their own format', async () => {
    const service = new AnalysisService();
    const { result } = await analyze(service, { kind: 'sample', sampleId: 'csv-web' });
    expect(result?.format).toBe('csv');
    expect(result?.parseOptions.mapping?.sourceIp).toBe('src_ip');
    expect(result?.detections.length).toBeGreaterThan(0);
  });

  it('rejects oversized input and unknown sources', async () => {
    const service = new AnalysisService();
    const big = await analyze(
      service,
      { kind: 'text', text: 'x'.repeat(MB + 1), name: 'big' },
      options({ limits: { ...DEFAULT_LIMITS, maxFileSizeBytes: MB } }),
    );
    expect(big.error).toMatchObject({ code: 'input_too_large' });
    expect(
      (await analyze(service, { kind: 'sample', sampleId: 'nope' as never })).error?.code,
    ).toBe('invalid_request');
    expect(
      (await analyze(service, { kind: 'file', file: 'not a blob' as never, name: 'x' })).error
        ?.code,
    ).toBe('invalid_request');
    expect((await call(service, { id: 3, type: 'bogus' } as never)).error?.code).toBe(
      'invalid_request',
    );
  });

  it('refuses queries without a dataset', async () => {
    const service = new AnalysisService();
    const r = await call(service, { id: 2, type: 'metrics', filter: {} });
    expect(r.error).toEqual({
      code: 'no_dataset',
      message: 'No dataset is loaded. Run a scan first.',
    });
  });

  it('answers filtered metrics, event pages, detection evidence and related events', async () => {
    const service = new AnalysisService();
    const { result: summary } = await analyze(service, { kind: 'sample', sampleId: 'ssh-auth' });
    const brute = summary!.detections.find(
      (d) => d.ruleId === 'AUTH-001' && d.sourceIps.includes('203.0.113.50'),
    )!;

    const metrics = await call<ResultMap['metrics']>(service, {
      id: 2,
      type: 'metrics',
      filter: { sourceIps: ['203.0.113.50'], timeZone: 'UTC' },
    });
    expect(metrics.result?.metrics.uniqueIps).toBe(1);
    expect(metrics.result?.detectionIdsInScope).toContain(brute.id);
    expect(metrics.result?.matchingEvents).toBe(metrics.result?.metrics.totalEvents);

    const page = await call<ResultMap['events']>(service, {
      id: 3,
      type: 'events',
      filter: { detectionIds: [brute.id] },
      sort: { field: 'timestamp', direction: 'desc' },
      page: 0,
      pageSize: 25,
    });
    expect(page.result?.total).toBe(brute.matchedEventCount);
    expect(page.result?.rows[0]!.timestamp).toBe(brute.end);

    const evidence = await call<ResultMap['detectionEvents']>(service, {
      id: 4,
      type: 'detectionEvents',
      detectionId: brute.id,
      page: 0,
      pageSize: 10,
    });
    expect(evidence.result?.rows[0]!.timestamp).toBe(brute.start);
    expect(
      (
        await call(service, {
          id: 5,
          type: 'detectionEvents',
          detectionId: 'missing',
          page: 0,
          pageSize: 10,
        })
      ).error?.code,
    ).toBe('invalid_request');

    const anchor = page.result!.rows[0]!.id;
    const related = await call<ResultMap['related']>(service, {
      id: 6,
      type: 'related',
      eventId: anchor,
      by: 'ip',
      windowMinutes: 5,
      limit: 20,
    });
    expect(related.result?.page.rows.every((r) => r.sourceIp === '203.0.113.50')).toBe(true);

    const byId = await call<ResultMap['eventsById']>(service, {
      id: 7,
      type: 'eventsById',
      ids: [anchor, -1, 1e9],
    });
    expect(byId.result?.map((e) => e.id)).toEqual([anchor]);
  });

  it('re-runs detections with a new configuration without re-parsing', async () => {
    const service = new AnalysisService();
    await analyze(service, { kind: 'text', text: BRUTE, name: 'paste' });
    const cfg = defaultDetectionConfig();
    cfg.rules['AUTH-001'].params.threshold = 50;
    const r = await call<ResultMap['redetect']>(service, {
      id: 2,
      type: 'redetect',
      detection: cfg,
      timeZone: 'UTC',
    });
    expect(r.result?.detections.some((d) => d.ruleId === 'AUTH-001')).toBe(false);
    const events = await call<ResultMap['events']>(service, {
      id: 3,
      type: 'events',
      filter: { detectionIds: [] },
      sort: { field: 'line', direction: 'asc' },
      page: 0,
      pageSize: 5,
    });
    expect(events.result?.total).toBe(0);
  });

  it('exports filtered events as CSV and ignores unknown filter keys', async () => {
    const service = new AnalysisService();
    await analyze(service, { kind: 'text', text: BRUTE, name: 'paste' });
    const r = await call<ResultMap['exportEvents']>(service, {
      id: 2,
      type: 'exportEvents',
      filter: { usernames: ['root'], evil: '<script>' } as never,
      includeRaw: false,
      timeZone: 'UTC',
    });
    expect(r.result?.rows).toBe(12);
    expect(r.result?.csv).not.toContain('Failed password');
  });

  it('discards the previous dataset when a new scan starts and on reset', async () => {
    const service = new AnalysisService();
    await analyze(service, { kind: 'text', text: BRUTE, name: 'first' });
    const second = await analyze(service, {
      kind: 'text',
      text: 'Oct 27 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2',
      name: 'second',
    });
    expect(second.result?.stats.eventsCreated).toBe(1);
    expect(second.result?.detections).toEqual([]);
    const metrics = await call<ResultMap['metrics']>(service, {
      id: 2,
      type: 'metrics',
      filter: {},
    });
    expect(metrics.result?.metrics.totalEvents).toBe(1);
    await call(service, { id: 3, type: 'reset' });
    expect(service.hasDataset).toBe(false);
  });

  it('handles empty input and input with no detections', async () => {
    const service = new AnalysisService();
    const { result } = await analyze(service, { kind: 'text', text: '', name: 'empty' });
    expect(result).toMatchObject({
      stats: { totalLines: 0, eventsCreated: 0 },
      detections: [],
      posture: { level: 'none' },
    });
  });

  it('validates untrusted options', async () => {
    expect(
      validateParseOptions({
        format: 'evil',
        timestamps: { assumedYear: 99999, sourceOffsetMinutes: 'x' },
        mapping: { timestamp: 't', bogus: 'y', username: 5 },
        csvDelimiter: '#',
      }),
    ).toEqual({
      format: 'linux-auth',
      timestamps: { assumedYear: 2100, sourceOffsetMinutes: 0 },
      mapping: { timestamp: 't' },
    });
    const service = new AnalysisService();
    const { result } = await analyze(service, { kind: 'text', text: BRUTE, name: 'x' }, {
      parse: null,
      limits: 'x',
      detection: 5,
      timeZone: 'mars',
    } as never);
    expect(result?.stats.eventsCreated).toBe(12);
  });

  it('converts unexpected exceptions into a generic error without data', async () => {
    const service = new AnalysisService();
    const responses: WorkerResponse[] = [];
    await service.handle(
      {
        id: 9,
        type: 'analyze',
        source: {
          kind: 'text',
          get text(): string {
            throw new TypeError('secret 203.0.113.50');
          },
          name: 'x',
        } as never,
        options: options(),
      },
      (r) => responses.push(r),
    );
    const last = responses[responses.length - 1]!;
    expect(last).toMatchObject({ id: 9, type: 'error', error: { code: 'internal' } });
    expect(JSON.stringify(last)).not.toContain('203.0.113.50');
  });
});
