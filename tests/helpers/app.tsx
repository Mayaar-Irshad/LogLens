import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../../src/app/App';
import type { WorkerFactory } from '../../src/workers/analysisClient';
import { createInProcessWorker } from '../../src/workers/inProcessWorker';

export function renderApp(workerFactory: WorkerFactory = () => createInProcessWorker()) {
  const user = userEvent.setup();
  const utils = render(<App workerFactory={workerFactory} />);
  return { user, ...utils };
}

export const nav = (name: string) =>
  within(screen.getByRole('navigation', { name: 'Main' })).getByRole('button', {
    name: new RegExp(`^${name}`),
  });

export async function analyzeSample(user: ReturnType<typeof userEvent.setup>, sampleName: string) {
  const card = screen.getByText(sampleName).closest('article')!;
  await user.click(within(card).getByRole('button', { name: 'Analyze sample' }));
  await screen.findByRole('heading', { name: 'Overview', level: 1 }, { timeout: 15000 });
}
