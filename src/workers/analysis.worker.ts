import { AnalysisService } from './analysisService';
import type { WorkerRequest, WorkerResponse } from './protocol';

/**
 * Dedicated worker entry point. All parsing, detection and aggregation runs
 * here so the UI thread stays responsive. A worker isolates CPU work, not
 * privileges: it shares the page's origin, so the same input-handling rules
 * apply here as on the main thread.
 */
const scope = self as unknown as {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage: (message: WorkerResponse) => void;
};

const service = new AnalysisService();

scope.onmessage = (event) => {
  void service.handle(event.data, (response) => scope.postMessage(response));
};
