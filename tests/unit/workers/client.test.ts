import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultDetectionConfig } from '../../../src/features/detection/config/detectionConfig';
import { DEFAULT_LIMITS } from '../../../src/features/log-ingestion/validation/limits';
import {
  AnalysisCancelledError,
  AnalysisClient,
  AnalysisTimeoutError,
  WorkerCrashedError,
  WorkerRequestError,
  type WorkerLike,
} from '../../../src/workers/analysisClient';
import { createInProcessWorker } from '../../../src/workers/inProcessWorker';
import type { AnalyzeOptions, WorkerRequest, WorkerResponse } from '../../../src/workers/protocol';

const options: AnalyzeOptions = {
  parse: { format: 'linux-auth', timestamps: { assumedYear: 2026, sourceOffsetMinutes: 0 } },
  limits: { ...DEFAULT_LIMITS, analysisTimeoutSeconds: 10 },
  detection: defaultDetectionConfig(),
  timeZone: 'UTC',
};

/** Controllable fake worker. */
class FakeWorker implements WorkerLike {
  onmessage: ((e: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  onmessageerror: ((e: MessageEvent) => void) | null = null;
  sent: WorkerRequest[] = [];
  terminated = false;
  postMessage(m: WorkerRequest): void {
    this.sent.push(m);
  }
  terminate(): void {
    this.terminated = true;
  }
  reply(r: WorkerResponse): void {
    this.onmessage?.({ data: r } as MessageEvent<WorkerResponse>);
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe('AnalysisClient with a fake worker', () => {
  const setup = () => {
    const workers: FakeWorker[] = [];
    const onCrash = vi.fn();
    const client = new AnalysisClient(
      () => {
        const w = new FakeWorker();
        workers.push(w);
        return w;
      },
      { queryTimeoutMs: 1000, onCrash },
    );
    return { client, workers, onCrash };
  };

  it('correlates responses and forwards progress', async () => {
    const { client, workers } = setup();
    const progress = vi.fn();
    const p = client.analyze({ kind: 'text', text: 'x', name: 'x' }, options, progress);
    const w = workers[0]!;
    const id = w.sent[0]!.id;
    w.reply({
      id,
      type: 'progress',
      progress: {
        phase: 'reading',
        bytesProcessed: 1,
        totalBytes: 1,
        linesProcessed: 1,
        eventsCreated: 0,
      },
    });
    w.reply({ id: id + 100, type: 'result', result: { ok: true } }); // stale/unknown id is ignored
    w.reply({ id, type: 'result', result: { ok: true } });
    await expect(p).resolves.toEqual({ ok: true });
    expect(progress).toHaveBeenCalledTimes(1);
    expect(client.busy).toBe(false);
  });

  it('surfaces worker-reported errors with their code', async () => {
    const { client, workers } = setup();
    const p = client.query({ type: 'metrics', filter: {} });
    workers[0]!.reply({
      id: workers[0]!.sent[0]!.id,
      type: 'error',
      error: { code: 'no_dataset', message: 'No dataset' },
    });
    await expect(p).rejects.toEqual(new WorkerRequestError('No dataset', 'no_dataset'));
  });

  it('cancels by terminating the worker and recreates one for the next request', async () => {
    const { client, workers, onCrash } = setup();
    const p = client.analyze({ kind: 'text', text: 'x', name: 'x' }, options);
    client.cancel();
    await expect(p).rejects.toBeInstanceOf(AnalysisCancelledError);
    expect(workers[0]!.terminated).toBe(true);
    expect(onCrash).not.toHaveBeenCalled();
    void client.query({ type: 'reset' }).catch(() => undefined);
    expect(workers).toHaveLength(2);
    client.dispose();
  });

  it('times out long-running analysis and terminates the worker', async () => {
    vi.useFakeTimers();
    const { client, workers, onCrash } = setup();
    const p = client.analyze(
      { kind: 'text', text: 'x', name: 'x' },
      { ...options, limits: { ...options.limits, analysisTimeoutSeconds: 10 } },
    );
    const assertion = expect(p).rejects.toBeInstanceOf(AnalysisTimeoutError);
    vi.advanceTimersByTime(10_001);
    await assertion;
    expect(workers[0]!.terminated).toBe(true);
    expect(onCrash).toHaveBeenCalledWith(expect.any(AnalysisTimeoutError));
  });

  it('rejects all pending requests when the worker crashes', async () => {
    const { client, workers, onCrash } = setup();
    const a = client.query({ type: 'metrics', filter: {} });
    const b = client.query({ type: 'reset' });
    workers[0]!.onerror?.(new Event('error'));
    await expect(a).rejects.toBeInstanceOf(WorkerCrashedError);
    await expect(b).rejects.toBeInstanceOf(WorkerCrashedError);
    expect(onCrash).toHaveBeenCalledTimes(1);
    expect(workers[0]!.terminated).toBe(true);
  });

  it('treats undecodable messages as a crash', async () => {
    const { client, workers } = setup();
    const a = client.query({ type: 'reset' });
    workers[0]!.onmessageerror?.(new MessageEvent('messageerror'));
    await expect(a).rejects.toBeInstanceOf(WorkerCrashedError);
  });

  it('a new scan cancels in-flight work from the previous scan', async () => {
    const { client, workers } = setup();
    const first = client.analyze({ kind: 'text', text: 'a', name: 'a' }, options);
    const firstAssertion = expect(first).rejects.toBeInstanceOf(AnalysisCancelledError);
    const second = client.analyze({ kind: 'text', text: 'b', name: 'b' }, options);
    await firstAssertion;
    expect(workers).toHaveLength(2);
    const w = workers[1]!;
    w.reply({ id: w.sent[0]!.id, type: 'result', result: { ok: true } });
    await expect(second).resolves.toEqual({ ok: true });
  });

  it('reports a request that cannot be posted', async () => {
    const client = new AnalysisClient(() => {
      const w = new FakeWorker();
      w.postMessage = () => {
        throw new DOMException('could not clone', 'DataCloneError');
      };
      return w;
    });
    await expect(client.query({ type: 'reset' })).rejects.toBeInstanceOf(WorkerRequestError);
  });
});

describe('AnalysisClient with the in-process worker', () => {
  it('runs repeated scans end to end with fresh state each time', async () => {
    const client = new AnalysisClient(() => createInProcessWorker());
    const lines = Array.from(
      { length: 10 },
      (_, i) =>
        `Oct 27 10:00:0${i} h sshd[1]: Failed password for root from 203.0.113.50 port ${i + 1} ssh2`,
    ).join('\n');
    const first = await client.analyze({ kind: 'text', text: lines, name: 'a' }, options);
    expect(first.detections.some((d) => d.ruleId === 'AUTH-001')).toBe(true);
    const second = await client.analyze(
      { kind: 'text', text: lines.split('\n')[0]!, name: 'b' },
      options,
    );
    expect(second.detections).toEqual([]);
    const m = await client.query({ type: 'metrics', filter: {} });
    expect(m.metrics.totalEvents).toBe(1);
    client.cancel();
    await expect(client.query({ type: 'metrics', filter: {} })).rejects.toMatchObject({
      code: 'no_dataset',
    });
  });
});
