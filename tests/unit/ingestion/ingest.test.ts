import { describe, expect, it } from 'vitest';
import { Ingestor } from '../../../src/features/log-ingestion/ingest';
import { LineSplitter, readBlobChunks } from '../../../src/features/log-ingestion/lineSplitter';
import {
  DEFAULT_LIMITS,
  LIMIT_SPECS,
  MB,
  validateLimits,
} from '../../../src/features/log-ingestion/validation/limits';
import {
  checkInputFile,
  checkPastedText,
  looksBinary,
} from '../../../src/features/log-ingestion/validation/fileChecks';
import { ingest, TEST_NOW, TEST_TIMESTAMPS } from '../../helpers/ingest';

const AUTH_LINE = (i: number) =>
  `Oct 27 10:00:${String(i % 60).padStart(2, '0')} h sshd[1]: Failed password for root from 192.0.2.1 port ${1000 + i} ssh2`;

describe('Ingestor accounting', () => {
  it('handles an empty input', () => {
    const r = ingest('', 'linux-auth');
    expect(r.events).toEqual([]);
    expect(r.stats.totalLines).toBe(0);
  });

  it('counts blank lines without creating events and strips a BOM', () => {
    const r = ingest(`\ufeff${AUTH_LINE(1)}\n\n   \n${AUTH_LINE(2)}\n`, 'linux-auth');
    expect(r.stats).toMatchObject({ totalLines: 4, blankLines: 2, parsedRecords: 2 });
    expect(r.events[0]?.raw.startsWith('Oct')).toBe(true);
  });

  it('handles CRLF and CR line endings', () => {
    const r = ingest(`${AUTH_LINE(1)}\r\n${AUTH_LINE(2)}\r${AUTH_LINE(3)}`, 'linux-auth');
    expect(r.events.map((e) => e.line)).toEqual([1, 2, 3]);
  });

  it('counts exact duplicates but keeps them as events', () => {
    const r = ingest([AUTH_LINE(1), AUTH_LINE(1), AUTH_LINE(1)].join('\n'), 'linux-auth');
    expect(r.events).toHaveLength(3);
    expect(r.stats.duplicateLines).toBe(2);
    expect(r.stats.warnings.find((w) => w.code === 'duplicate_lines')?.count).toBe(2);
  });

  it('rejects over-long lines without parsing them', () => {
    const long = `${AUTH_LINE(1)} ${'A'.repeat(3000)}`;
    const r = ingest(`${long}\n${AUTH_LINE(2)}`, 'linux-auth', { limits: { maxLineLength: 1024 } });
    expect(r.stats).toMatchObject({ rejectedRecords: 1, parsedRecords: 1 });
    expect(r.rejected[0]).toMatchObject({ line: 1, reason: 'line_too_long', length: long.length });
    expect(r.rejected[0]!.preview.length).toBeLessThanOrEqual(160);
  });

  it('stops analyzing at the event limit and counts the remaining lines', () => {
    const lines = Array.from({ length: 1500 }, (_, i) => AUTH_LINE(i));
    const r = ingest(lines.join('\n'), 'linux-auth', { limits: { maxEvents: 1000 } });
    expect(r.events).toHaveLength(1000);
    expect(r.limitReached).toBe(true);
    expect(r.stats.unprocessedLines).toBe(500);
    expect(r.stats.warnings.find((w) => w.code === 'event_limit')?.message).toMatch(
      /1,000.*line 1,000.*500/,
    );
  });

  it('stops mid-expansion when a repeated message crosses the limit', () => {
    const lines = [
      ...Array.from({ length: 998 }, (_, i) => AUTH_LINE(i)),
      'Oct 27 10:00:00 h sshd[1]: message repeated 5 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]',
      AUTH_LINE(1),
    ];
    const r = ingest(lines.join('\n'), 'linux-auth', { limits: { maxEvents: 1000 } });
    expect(r.events).toHaveLength(1000);
    expect(r.stats.unprocessedLines).toBe(1);
  });

  it('bounds the number of rejected samples but counts all rejections', () => {
    const r = ingest(Array.from({ length: 30 }, (_, i) => `junk ${i}`).join('\n'), 'linux-auth', {
      limits: { maxRejectedSamples: 10 },
    });
    expect(r.stats.rejectedRecords).toBe(30);
    expect(r.rejected).toHaveLength(10);
  });

  it('warns about timestamps in the future (likely a wrong assumed year)', () => {
    const r = ingest(AUTH_LINE(1), 'linux-auth', { assumedYear: 2030 });
    expect(r.stats.warnings.map((w) => w.code)).toContain('future_timestamps');
  });

  it('assigns sequential ids and records the format', () => {
    const r = ingest([AUTH_LINE(1), 'junk', AUTH_LINE(2)].join('\n'), 'linux-auth');
    expect(r.events.map((e) => [e.id, e.line, e.format])).toEqual([
      [0, 1, 'linux-auth'],
      [1, 3, 'linux-auth'],
    ]);
  });

  it('counts overlong lines reported by the splitter', () => {
    const ingestor = new Ingestor({
      parse: { format: 'linux-auth', timestamps: TEST_TIMESTAMPS },
      limits: DEFAULT_LIMITS,
      now: TEST_NOW,
    });
    ingestor.pushOverlong('AAAA', 50_000);
    ingestor.pushLine(AUTH_LINE(1));
    const r = ingestor.finish();
    expect(r.rejected[0]).toMatchObject({ line: 1, reason: 'line_too_long', length: 50_000 });
    expect(r.events[0]?.line).toBe(2);
  });

  it('handles mixed valid, partial and invalid records consistently', () => {
    const r = ingest(
      [
        AUTH_LINE(1),
        'garbage',
        'Oct 99 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2',
        '',
      ].join('\n'),
      'linux-auth',
    );
    const s = r.stats;
    expect(
      s.parsedRecords + s.partialRecords + s.rejectedRecords + s.blankLines + s.skippedLines,
    ).toBe(s.totalLines);
    expect(s).toMatchObject({ parsedRecords: 1, partialRecords: 1, rejectedRecords: 1 });
  });
});

describe('LineSplitter', () => {
  it('splits across chunk boundaries including split CRLF pairs', () => {
    const s = new LineSplitter(1000);
    const out = [...s.push('a\r'), ...s.push('\nb\nc'), ...s.push('d\r\n'), ...s.finish()];
    expect(out).toEqual([
      { kind: 'line', text: 'a' },
      { kind: 'line', text: 'b' },
      { kind: 'line', text: 'cd' },
    ]);
  });

  it('bounds memory for very long lines', () => {
    const s = new LineSplitter(10);
    const out = [...s.push('0123456789ABCDEF'), ...s.push('GHIJ\nok'), ...s.finish()];
    expect(out[0]).toMatchObject({ kind: 'overlong', length: 20 });
    expect(out[1]).toEqual({ kind: 'line', text: 'ok' });
  });

  it('emits empty lines between consecutive newlines', () => {
    const s = new LineSplitter(100);
    expect(
      [...s.push('a\n\nb'), ...s.finish()].map((i) => (i.kind === 'line' ? i.text : '?')),
    ).toEqual(['a', '', 'b']);
  });

  it('reads blobs in chunks and decodes multi-byte characters across boundaries', async () => {
    const blob = new Blob([new Uint8Array([0xef, 0xbb, 0xbf]), 'héllo\n', 'wörld']);
    let text = '';
    let bytes = 0;
    for await (const chunk of readBlobChunks(blob)) {
      text += chunk.text;
      bytes += chunk.bytes;
    }
    expect(text).toBe('héllo\nwörld');
    expect(bytes).toBe(blob.size);
  });
});

describe('limits and input checks', () => {
  it('clamps untrusted limit settings', () => {
    const l = validateLimits({
      maxFileSizeBytes: 10 * 1024 * MB,
      maxLineLength: 'abc',
      maxEvents: 1500.6,
      analysisTimeoutSeconds: -1,
    });
    expect(l.maxFileSizeBytes).toBe(LIMIT_SPECS.maxFileSizeBytes.max);
    expect(l.maxLineLength).toBe(DEFAULT_LIMITS.maxLineLength);
    expect(l.maxEvents).toBe(1501);
    expect(l.analysisTimeoutSeconds).toBe(10);
    expect(validateLimits(null)).toEqual(DEFAULT_LIMITS);
  });

  it('defaults to a 25 MB input limit', () => {
    expect(DEFAULT_LIMITS.maxFileSizeBytes).toBe(25 * MB);
  });

  it('checks files before reading them', () => {
    expect(checkInputFile({ name: 'auth.log', size: 0 }, MB).error).toMatch(/empty/);
    expect(checkInputFile({ name: 'auth.log', size: 2 * MB }, MB).error).toMatch(
      /exceeds the 1.0 MB limit/,
    );
    expect(checkInputFile({ name: 'auth.log.gz', size: 100 }, MB).error).toMatch(/Compressed/);
    expect(checkInputFile({ name: 'Security.evtx', size: 100 }, MB).error).toMatch(/evtx/);
    expect(checkInputFile({ name: 'image.png', size: 100 }, MB)).toMatchObject({
      ok: true,
      warnings: [expect.stringMatching(/non-text/)],
    });
    expect(checkInputFile({ name: 'access.log', size: 100 }, MB)).toEqual({
      ok: true,
      warnings: [],
    });
  });

  it('checks pasted text', () => {
    expect(checkPastedText('   ', MB).ok).toBe(false);
    expect(checkPastedText('x'.repeat(2 * MB), MB).error).toMatch(/exceeds/);
    expect(checkPastedText('line', MB).ok).toBe(true);
  });

  it('detects binary content', () => {
    expect(looksBinary('normal text\nlines\t')).toBe(false);
    expect(looksBinary('abc\u0000def')).toBe(true);
    expect(looksBinary('\u0001\u0002\u0003abc')).toBe(true);
    expect(looksBinary('')).toBe(false);
  });
});
