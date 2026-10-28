import type {
  AnalysisSummary,
  AnalyzeOptions,
  AnalyzeSource,
  ResultMap,
  ScanProgress,
  WorkerErrorCode,
  WorkerRequest,
  WorkerResponse,
} from './protocol';

/** The subset of the Worker API the client depends on (lets tests inject fakes). */
export interface WorkerLike {
  postMessage(message: WorkerRequest): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null;
  onerror: ((event: Event) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
}

export type WorkerFactory = () => WorkerLike;

export class AnalysisCancelledError extends Error {
  constructor() {
    super('The scan was cancelled.');
    this.name = 'AnalysisCancelledError';
  }
}

export class AnalysisTimeoutError extends Error {
  constructor(seconds: number) {
    super(
      `The operation did not finish within ${seconds} seconds and was stopped. Try a smaller file or raise the timeout in Settings.`,
    );
    this.name = 'AnalysisTimeoutError';
  }
}

export class WorkerCrashedError extends Error {
  constructor(detail?: string) {
    super(
      `The analysis worker stopped unexpectedly${detail ? ` (${detail})` : ''}. The dataset was discarded; please run the scan again.`,
    );
    this.name = 'WorkerCrashedError';
  }
}

export class WorkerRequestError extends Error {
  constructor(
    message: string,
    readonly code: WorkerErrorCode,
  ) {
    super(message);
    this.name = 'WorkerRequestError';
  }
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  onProgress?: (p: ScanProgress) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** Omit that distributes over a union, so each request variant keeps its own fields. */
type WithoutId<T> = T extends unknown ? Omit<T, 'id'> : never;
type RequestBody = WithoutId<WorkerRequest>;
type QueryBody = WithoutId<Exclude<WorkerRequest, { type: 'analyze' }>>;

/**
 * Main-thread client for the analysis worker. Adds request correlation,
 * per-request timeouts, cancellation (by terminating the worker, which is the
 * only way to interrupt synchronous work), and crash recovery. After a
 * cancel, timeout or crash the worker is discarded and a fresh one is created
 * lazily on the next request, so state never leaks between scans.
 */
export class AnalysisClient {
  private worker: WorkerLike | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  private crashHandler: ((error: Error) => void) | undefined;

  constructor(
    private readonly factory: WorkerFactory,
    private readonly options: { queryTimeoutMs?: number; onCrash?: (error: Error) => void } = {},
  ) {
    this.crashHandler = options.onCrash;
  }

  /** Register the callback for worker crashes and timeouts (not for user cancellation). */
  setCrashHandler(handler: ((error: Error) => void) | undefined): void {
    this.crashHandler = handler;
  }

  private ensureWorker(): WorkerLike {
    if (this.worker) return this.worker;
    const worker = this.factory();
    worker.onmessage = (event) => this.handleMessage(event.data);
    worker.onerror = (event) => {
      event.preventDefault?.();
      this.fail(new WorkerCrashedError('runtime error'));
    };
    worker.onmessageerror = () => this.fail(new WorkerCrashedError('message could not be decoded'));
    this.worker = worker;
    return worker;
  }

  private handleMessage(message: WorkerResponse): void {
    const pending = this.pending.get(message?.id);
    if (!pending) return; // stale response from a cancelled request
    if (message.type === 'progress') {
      pending.onProgress?.(message.progress);
      return;
    }
    clearTimeout(pending.timer);
    this.pending.delete(message.id);
    if (message.type === 'result') pending.resolve(message.result);
    else pending.reject(new WorkerRequestError(message.error.message, message.error.code));
  }

  /** Terminate the worker and reject everything in flight with `error`. */
  private fail(error: Error): void {
    this.destroyWorker();
    const entries = [...this.pending.values()];
    this.pending.clear();
    for (const p of entries) {
      clearTimeout(p.timer);
      p.reject(error);
    }
    if (!(error instanceof AnalysisCancelledError)) this.crashHandler?.(error);
  }

  private destroyWorker(): void {
    if (!this.worker) return;
    this.worker.onmessage = null;
    this.worker.onerror = null;
    this.worker.onmessageerror = null;
    this.worker.terminate();
    this.worker = null;
  }

  private send<T>(
    request: RequestBody,
    timeoutMs: number,
    onProgress?: (p: ScanProgress) => void,
  ): Promise<T> {
    const worker = this.ensureWorker();
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new AnalysisTimeoutError(Math.round(timeoutMs / 1000)));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
        timer,
        ...(onProgress ? { onProgress } : {}),
      });
      try {
        worker.postMessage({ ...request, id });
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(
          new WorkerRequestError(
            'The input could not be sent to the analysis worker.',
            'invalid_request',
          ),
        );
      }
    });
  }

  analyze(
    source: AnalyzeSource,
    options: AnalyzeOptions,
    onProgress?: (p: ScanProgress) => void,
  ): Promise<AnalysisSummary> {
    // Any in-flight work belongs to the previous dataset: discard it.
    if (this.pending.size > 0) this.fail(new AnalysisCancelledError());
    return this.send<AnalysisSummary>(
      { type: 'analyze', source, options },
      options.limits.analysisTimeoutSeconds * 1000,
      onProgress,
    );
  }

  query<R extends QueryBody>(request: R): Promise<ResultMap[R['type']]> {
    return this.send<ResultMap[R['type']]>(request, this.options.queryTimeoutMs ?? 60_000);
  }

  /** Stop all work immediately. Pending promises reject with AnalysisCancelledError. */
  cancel(): void {
    this.fail(new AnalysisCancelledError());
  }

  get busy(): boolean {
    return this.pending.size > 0;
  }

  dispose(): void {
    this.cancel();
  }
}
