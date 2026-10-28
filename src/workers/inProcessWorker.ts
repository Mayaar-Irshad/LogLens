import { AnalysisService } from './analysisService';
import type { WorkerLike } from './analysisClient';
import type { WorkerRequest, WorkerResponse } from './protocol';

const clone = <T>(value: T): T =>
  typeof structuredClone === 'function' ? structuredClone(value) : value;

/**
 * In-process stand-in with the same message semantics as a worker. Used by
 * tests and as a fallback when Web Workers are unavailable (analysis then
 * runs on the main thread and the UI may pause on large inputs).
 */
export function createInProcessWorker(service = new AnalysisService()): WorkerLike {
  let terminated = false;
  const worker: WorkerLike = {
    onmessage: null,
    onerror: null,
    onmessageerror: null,
    postMessage(message: WorkerRequest) {
      if (terminated) return;
      setTimeout(() => {
        if (terminated) return;
        void service.handle(message, (response: WorkerResponse) => {
          if (terminated) return;
          const data = clone(response);
          setTimeout(() => {
            if (!terminated) worker.onmessage?.({ data } as MessageEvent<WorkerResponse>);
          }, 0);
        });
      }, 0);
    },
    terminate() {
      terminated = true;
      service.reset();
    },
  };
  return worker;
}
