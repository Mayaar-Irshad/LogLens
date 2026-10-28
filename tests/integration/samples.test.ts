import { describe, expect, it } from 'vitest';
import { defaultDetectionConfig } from '../../src/features/detection/config/detectionConfig';
import { runDetections } from '../../src/features/detection/engine/runDetections';
import { ingestText } from '../../src/features/log-ingestion/ingest';
import { runPreflight } from '../../src/features/log-ingestion/preflight';
import { DEFAULT_LIMITS } from '../../src/features/log-ingestion/validation/limits';
import {
  generateSample,
  SAMPLE_YEAR,
  SAMPLES,
  type SampleId,
} from '../../src/features/sample-data/samples';

/**
 * End-to-end expectations for the bundled synthetic samples. These are the
 * results documented in the README; if a rule changes behaviour, this test
 * shows exactly how.
 */
function analyzeSample(id: SampleId) {
  const info = SAMPLES.find((s) => s.id === id)!;
  const text = generateSample(id);
  const ingest = ingestText(text, {
    parse: {
      format: info.format,
      timestamps: { assumedYear: SAMPLE_YEAR, sourceOffsetMinutes: 0 },
      ...(info.mapping ? { mapping: info.mapping } : {}),
    },
    limits: DEFAULT_LIMITS,
    now: Date.UTC(2026, 9, 28),
  });
  const run = runDetections(ingest.events, defaultDetectionConfig(), { stats: ingest.stats });
  return {
    text,
    ingest,
    run,
    has: (ruleId: string, subject?: string) =>
      run.detections.some(
        (d) =>
          d.ruleId === ruleId &&
          (!subject ||
            d.subjects.ips.includes(subject) ||
            d.subjects.users.includes(subject) ||
            d.sourceIps.includes(subject)),
      ),
  };
}

describe('sample datasets', () => {
  it('are deterministic', () => {
    for (const s of SAMPLES) expect(generateSample(s.id)).toBe(generateSample(s.id));
  });

  it('only use documentation IP ranges', () => {
    for (const s of SAMPLES) {
      const ips = generateSample(s.id).match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [];
      for (const ip of ips)
        expect(ip).toMatch(
          /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$|^0\.0\.0\.0$|^10\.0\.0\.1$/,
        );
    }
  });

  it('are detected as their own format by preflight', () => {
    for (const s of SAMPLES) {
      const p = runPreflight(generateSample(s.id).slice(0, 64 * 1024), {
        truncated: true,
        fileName: s.fileName,
      });
      expect(p.detection.format).toBe(s.format);
    }
  });

  it('ssh-auth: brute force with compromise, spraying and distributed guessing', () => {
    const r = analyzeSample('ssh-auth');
    expect(r.ingest.stats.rejectedRecords).toBe(2);
    expect(r.ingest.stats.partialRecords).toBe(1);
    expect(r.ingest.stats.expandedRepeats).toBeGreaterThan(0);
    expect(r.has('AUTH-001', '203.0.113.50')).toBe(true);
    expect(r.has('AUTH-004', 'deploy')).toBe(true);
    expect(r.has('AUTH-003', '203.0.113.77')).toBe(true);
    expect(r.has('AUTH-005')).toBe(true);
    expect(r.has('AUTH-007', '203.0.113.50')).toBe(true);
    const corr = r.run.detections.find(
      (d) => d.ruleId === 'GEN-003' && d.subjects.ips.includes('203.0.113.50'),
    );
    expect(corr?.severity).toBe('critical');
    // Legitimate staff logins are not flagged as brute force.
    expect(
      r.run.detections.some(
        (d) => d.ruleId === 'AUTH-001' && d.sourceIps.some((ip) => ip.startsWith('198.51.100.')),
      ),
    ).toBe(false);
  });

  it('nginx-access: discovery with exposed file, injection probes, login guessing, outage, crawler', () => {
    const r = analyzeSample('nginx-access');
    const exposure = r.run.detections.find(
      (d) => d.ruleId === 'WEB-003' && d.sourceIps.includes('203.0.113.9'),
    );
    expect(exposure).toMatchObject({
      severity: 'high',
      title: 'Sensitive file served to 203.0.113.9',
    });
    expect(r.has('WEB-004', '203.0.113.9')).toBe(true);
    expect(r.has('WEB-009', '203.0.113.9')).toBe(true);
    expect(r.has('WEB-005', '203.0.113.9')).toBe(true);
    expect(r.has('WEB-008', '198.51.100.66')).toBe(true);
    expect(r.has('WEB-007', '192.0.2.150')).toBe(true);
    expect(r.has('WEB-002')).toBe(true);
    expect(r.has('WEB-006', '198.51.100.200')).toBe(true);
    expect(r.ingest.stats.partialRecords).toBe(1); // TLS handshake on the HTTP port
  });

  it('jsonl-auth: distributed guessing and success after failures', () => {
    const r = analyzeSample('jsonl-auth');
    expect(r.ingest.stats.rejectedRecords).toBe(2);
    expect(r.has('AUTH-005')).toBe(true);
    const compromise = r.run.detections.find(
      (d) => d.ruleId === 'AUTH-004' && d.subjects.ips.includes('203.0.113.120'),
    );
    expect(compromise).toMatchObject({ severity: 'high', subjects: { users: ['j.smith'] } });
  });

  it('csv-web: sqlmap probing and safe handling of a formula-like value', () => {
    const r = analyzeSample('csv-web');
    expect(r.ingest.stats.rejectedRecords).toBe(0);
    expect(r.has('WEB-008', '203.0.113.33')).toBe(true);
    expect(r.has('WEB-009', '203.0.113.33')).toBe(true);
    expect(r.ingest.events.some((e) => e.http?.userAgent?.startsWith('=HYPERLINK'))).toBe(true);
  });
});
