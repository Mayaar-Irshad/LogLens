import { describe, expect, it } from 'vitest';
import {
  buildReport,
  REPORT_SCHEMA,
  serializeReport,
  type ReportInput,
} from '../../../src/features/reporting/report';
import { clearFilters } from '../../../src/features/investigation/filters';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { AnalysisService } from '../../../src/workers/analysisService';
import type { AnalysisSummary, ResultMap, WorkerResponse } from '../../../src/workers/protocol';
import { DEFAULT_LIMITS } from '../../../src/features/log-ingestion/validation/limits';
import { buildFilename, safeFilenamePart, timestampForFilename } from '../../../src/utils/download';

const XSS_USER = '<script>alert(1)</script>';
const LINES = [
  ...Array.from(
    { length: 12 },
    (_, i) =>
      `Oct 27 10:00:${String(i).padStart(2, '0')} h sshd[1]: Failed password for invalid user ${XSS_USER} from 203.0.113.50 port ${i + 1} ssh2`,
  ),
  'Oct 27 10:01:00 h sshd[1]: Accepted password for alice from 203.0.113.50 port 99 ssh2',
].join('\n');

async function summary(): Promise<AnalysisSummary> {
  const service = new AnalysisService(() => Date.UTC(2026, 9, 27, 12));
  let result: AnalysisSummary | undefined;
  await service.handle(
    {
      id: 1,
      type: 'analyze',
      source: { kind: 'text', text: LINES, name: '../../etc/<evil>.log' },
      options: {
        parse: { format: 'linux-auth', timestamps: { assumedYear: 2026, sourceOffsetMinutes: 0 } },
        limits: DEFAULT_LIMITS,
        detection: defaultDetectionConfig(),
        timeZone: 'UTC',
      },
    },
    (r: WorkerResponse) => {
      if (r.type === 'result') result = r.result as ResultMap['analyze'];
    },
  );
  return result!;
}

function input(s: AnalysisSummary, overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    appVersion: '1.0.0',
    generatedAt: Date.UTC(2026, 9, 27, 12, 30),
    timeZone: 'UTC',
    summary: s,
    detections: s.detections,
    ruleRuns: s.ruleRuns,
    entities: s.entities,
    posture: s.posture,
    metrics: s.metrics,
    detectionConfig: defaultDetectionConfig(),
    filters: null,
    statuses: { [s.detections[0]!.id]: 'reviewed' },
    notes: { [s.detections[0]!.id]: 'confirmed with owner' },
    caseNote: 'Summary note',
    evidence: new Map(
      s.detections.map((d) => [
        d.id,
        d.eventIds.slice(0, 3).map((id) => ({
          id,
          line: id + 1,
          format: 'linux-auth' as const,
          category: 'authentication' as const,
          action: 'ssh_login_failed',
          timestamp: Date.UTC(2026, 9, 27, 10),
          sourceIp: '203.0.113.50',
          username: XSS_USER,
          raw: `raw line ${id} ${XSS_USER}`,
          status: 'parsed' as const,
        })),
      ]),
    ),
    options: { includeNotes: true, includeRawEvidence: false },
    ...overrides,
  };
}

describe('JSON report', () => {
  it('contains the required sections', async () => {
    const s = await summary();
    const r = buildReport(input(s));
    expect(r.schema).toBe(REPORT_SCHEMA);
    expect(r.application).toEqual({ name: 'LogLens', version: '1.0.0' });
    expect(r.generatedAt).toBe('2026-10-27T12:30:00.000Z');
    expect(r.scan.format).toBe('linux-auth');
    expect(r.scan.parsing.eventsCreated).toBe(13);
    expect(r.analysisTimeRange).toEqual({
      start: '2026-10-27T10:00:00.000Z',
      end: '2026-10-27T10:01:00.000Z',
    });
    expect(r.metrics.totalEvents).toBe(13);
    expect(r.scope).toEqual({ type: 'full-dataset' });
    expect(r.detections.length).toBe(s.detections.length);
    const d = r.detections[0]!;
    expect(d).toMatchObject({ analystStatus: 'reviewed', analystNote: 'confirmed with owner' });
    expect(d.reason.length).toBeGreaterThan(10);
    expect(d.recommendations.length).toBeGreaterThan(0);
    expect(d.falsePositiveConsiderations.length).toBeGreaterThan(0);
    expect(d.eventReferences).toHaveLength(3);
    expect(r.limitations.some((l) => l.includes('not confirmed incidents'))).toBe(true);
    expect(r.limitations.some((l) => l.includes('2026 was assumed'))).toBe(true);
    expect(r.investigationNote).toBe('Summary note');
  });

  it('excludes raw log lines unless explicitly requested, and can omit notes', async () => {
    const s = await summary();
    const without = buildReport(input(s));
    expect(JSON.stringify(without)).not.toContain('raw line');
    expect(without.privacy).toEqual({
      generatedLocally: true,
      rawLogLinesIncluded: false,
      analystNotesIncluded: true,
    });
    const withRaw = buildReport(
      input(s, { options: { includeNotes: false, includeRawEvidence: true } }),
    );
    expect(withRaw.detections[0]!.eventReferences[0]).toHaveProperty('rawLogLine');
    expect(withRaw.detections[0]).not.toHaveProperty('analystNote');
    expect(withRaw).not.toHaveProperty('investigationNote');
  });

  it('records filtered scope', async () => {
    const s = await summary();
    const r = buildReport(
      input(s, {
        filters: {
          ...clearFilters(),
          sourceIps: ['203.0.113.50'],
          timeRange: { start: Date.UTC(2026, 9, 27) },
        },
      }),
    );
    expect(r.scope).toEqual({
      type: 'filtered',
      filters: {
        sourceIps: ['203.0.113.50'],
        timeRange: { start: '2026-10-27T00:00:00.000Z', end: null },
      },
    });
  });

  it('serializes to valid JSON with HTML-significant characters escaped', async () => {
    const s = await summary();
    const text = serializeReport(buildReport(input(s)));
    expect(text).not.toMatch(/[<>&\u2028\u2029]/);
    expect(text).toContain('\\u003cscript\\u003e');
    const parsed = JSON.parse(text) as { detections: Array<{ usernames: string[] }> };
    expect(parsed.detections.some((d) => d.usernames.includes(XSS_USER))).toBe(true);
    expect(JSON.parse(serializeReport({ s: 'a\u2028b&' }))).toEqual({ s: 'a\u2028b&' });
  });
});

describe('download helpers', () => {
  it('produces safe filenames from untrusted names', () => {
    expect(safeFilenamePart('../../etc/<evil>.log')).toBe('etc-evil-.log');
    expect(safeFilenamePart('...')).toBe('logs');
    expect(safeFilenamePart('a'.repeat(100))).toHaveLength(40);
    expect(safeFilenamePart('café access.log')).toBe('cafe-access.log');
    expect(timestampForFilename(Date.UTC(2026, 9, 27, 12, 30, 5))).toBe('20261027-123005Z');
    expect(
      buildFilename('report', '../../secret/<x>.log', Date.UTC(2026, 9, 27, 12, 30, 5), 'json'),
    ).toBe('loglens-report-secret-x-20261027-123005Z.json');
  });
});
