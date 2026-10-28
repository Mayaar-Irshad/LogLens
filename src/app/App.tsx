import type { WorkerFactory } from '../workers/analysisClient';
import { AppShell } from '../components/layout/AppShell';
import { AppProvider } from './AppContext';

export function App({ workerFactory }: { workerFactory?: WorkerFactory }) {
  return (
    <AppProvider {...(workerFactory ? { workerFactory } : {})}>
      <AppShell />
    </AppProvider>
  );
}
