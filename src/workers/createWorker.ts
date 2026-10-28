import type { WorkerFactory, WorkerLike } from './analysisClient';
import type { WorkerRequest } from './protocol';

/** Real dedicated worker. Vite bundles the worker and rewrites this URL for the configured base path. */
export const createAnalysisWorker: WorkerFactory = () =>
  new Worker(new URL('./analysis.worker.ts', import.meta.url), {
    type: 'module',
    name: 'loglens-analysis',
  }) as unknown as WorkerLike;

export function supportsWorkers(): boolean {
  return typeof Worker !== 'undefined';
}

/**
 * Fallback for browsers without Web Workers: loads the analysis engine on
 * demand (so it is not part of the main bundle) and queues messages until
 * it is ready.
 */
export const createLazyInProcessWorker: WorkerFactory = () => {
  let inner: WorkerLike | null = null;
  let terminated = false;
  const queue: WorkerRequest[] = [];
  const proxy: WorkerLike = {
    onmessage: null,
    onerror: null,
    onmessageerror: null,
    postMessage(message) {
      if (inner) inner.postMessage(message);
      else queue.push(message);
    },
    terminate() {
      terminated = true;
      inner?.terminate();
    },
  };
  void import('./inProcessWorker').then(
    ({ createInProcessWorker }) => {
      if (terminated) return;
      inner = createInProcessWorker();
      inner.onmessage = (e) => proxy.onmessage?.(e);
      for (const m of queue.splice(0)) inner.postMessage(m);
    },
    () => proxy.onerror?.(new Event('error')),
  );
  return proxy;
};
