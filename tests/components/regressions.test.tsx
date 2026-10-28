import { act, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { WorkerLike } from '../../src/workers/analysisClient';
import type { WorkerRequest, WorkerResponse } from '../../src/workers/protocol';
import { AnalysisService } from '../../src/workers/analysisService';
import { createInProcessWorker } from '../../src/workers/inProcessWorker';
import { analyzeSample, nav, renderApp } from '../helpers/app';

/** Regressions for findings from an independent UI review. */

describe('investigation flow', () => {
  it('pivots replace the current filters instead of adding to them', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    await user.selectOptions(await screen.findByLabelText('Rule'), 'AUTH-001');
    expect(await screen.findByText('Rule: AUTH-001')).toBeInTheDocument();
    const detail = await screen.findByRole('article', { name: /Repeated failed logins/ });
    await user.click(within(detail).getByRole('button', { name: /Events ±15 min/ }));
    await screen.findByRole('heading', { name: 'Event explorer' });
    expect(screen.queryByText('Rule: AUTH-001')).not.toBeInTheDocument();
    expect(screen.getByText(/^Time: /)).toBeInTheDocument();
  }, 20000);

  it('opens a detection hidden by filters and says so, instead of showing another one', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    await user.selectOptions(await screen.findByLabelText('Rule'), 'AUTH-001');
    await user.click(nav('Event explorer'));
    const table = await screen.findByRole('table', { name: 'Parsed events' });
    await user.click(within(table).getAllByRole('button', { name: /Open event \d+ details/ })[0]!);
    const panel = await screen.findByRole('region', { name: /Event #/ });
    await user.click(await within(panel).findByRole('button', { name: /flagged by 3 rules/ }));
    expect(
      await screen.findByText('This detection is hidden by the current filters.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('article', { name: /flagged by 3 rules/ })).toBeInTheDocument();
  }, 20000);

  it('returns focus to the row after closing event details', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Event explorer'));
    const table = await screen.findByRole('table', { name: 'Parsed events' });
    const opener = within(table).getAllByRole('button', { name: /Open event \d+ details/ })[2]!;
    await user.click(opener);
    await user.click(await screen.findByRole('button', { name: 'Close event details' }));
    await waitFor(() => expect(document.activeElement).toBe(opener));
  }, 20000);

  it('focuses the event drawer on open and closes it with Escape', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Event explorer'));
    const table = await screen.findByRole('table', { name: 'Parsed events' });
    const opener = within(table).getAllByRole('button', { name: /Open event \d+ details/ })[1]!;
    await user.click(opener);
    const close = await screen.findByRole('button', { name: 'Close event details' });
    await waitFor(() => expect(document.activeElement).toBe(close));
    await user.keyboard('{Escape}');
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Close event details' })).toBeNull(),
    );
    await waitFor(() => expect(document.activeElement).toBe(opener));
  }, 20000);

  it('opens a ?sample= deep link on the view named in the hash', async () => {
    window.history.replaceState(null, '', '/?sample=nginx-access#/web');
    renderApp();
    expect(
      await screen.findByRole('heading', { name: 'Web activity', level: 1 }, { timeout: 15000 }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe('#/web');
  }, 20000);
});

describe('filter controls report their real state', () => {
  it('shows several selected severities instead of "Any", and Add never removes', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    const severity = await screen.findByRole('group', { name: 'Severity' });
    await user.click(within(severity).getByRole('checkbox', { name: /Critical/ }));
    await user.click(within(severity).getByRole('checkbox', { name: /High/ }));
    await user.click(nav('Event explorer'));
    expect(await screen.findByLabelText('Detection severity')).toHaveDisplayValue('2 selected');
    const user2 = screen.getByLabelText('Username');
    await user.type(user2, 'root');
    await user.click(within(user2.closest('form')!).getByRole('button', { name: 'Add' }));
    await user.type(user2, 'root');
    await user.click(within(user2.closest('form')!).getByRole('button', { name: 'Add' }));
    expect(screen.getByText('User: root')).toBeInTheDocument();
  }, 20000);

  it('Clear all also drops a search that has not been applied yet', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(screen.getByRole('button', { name: /^critical/ }));
    await user.type(screen.getByRole('searchbox'), 'Failed');
    await user.click(screen.getByRole('button', { name: 'Clear all filters' }));
    expect(screen.getByRole('searchbox')).toHaveValue('');
    await new Promise((r) => setTimeout(r, 400));
    expect(screen.queryByRole('button', { name: 'Clear all filters' })).not.toBeInTheDocument();
  }, 20000);

  it('lets the analyst type an assumed year and blocks invalid ones', async () => {
    const { user } = renderApp();
    await user.click(screen.getByLabelText('Log lines to analyze'));
    await user.paste(
      'Oct 27 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2',
    );
    await user.click(screen.getByRole('button', { name: 'Inspect pasted text' }));
    const year = await screen.findByLabelText('Assumed year');
    await user.clear(year);
    await user.type(year, '2025');
    expect(year).toHaveValue('2025');
    await user.clear(year);
    await user.type(year, '20');
    expect(screen.getByRole('button', { name: 'Analyze locally' })).toBeDisabled();
    expect(screen.getByText(/four-digit year/)).toBeInTheDocument();
  });

  it('keeps the report scope selection in line with the filters', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(screen.getByRole('button', { name: /^critical/ }));
    await user.click(nav('Report & export'));
    await user.click(screen.getByRole('radio', { name: /Current filtered view/ }));
    await user.click(screen.getByRole('button', { name: 'Clear all filters' }));
    expect(screen.getByRole('radio', { name: /Full dataset/ })).toBeChecked();
  }, 20000);
});

/** Delegates to a real service but can fail chosen request types. */
function flakyWorker(failTypes: Set<string>): () => WorkerLike {
  const service = new AnalysisService();
  return () => {
    const inner = createInProcessWorker(service);
    const w: WorkerLike = {
      onmessage: null,
      onerror: null,
      onmessageerror: null,
      postMessage(m: WorkerRequest) {
        if (failTypes.has(m.type)) {
          setTimeout(() =>
            w.onmessage?.({
              data: {
                id: m.id,
                type: 'error',
                error: { code: 'internal', message: 'Simulated failure.' },
              },
            } as MessageEvent<WorkerResponse>),
          );
          return;
        }
        inner.postMessage(m);
      },
      terminate: () => inner.terminate(),
    };
    inner.onmessage = (e) => w.onmessage?.(e);
    return w;
  };
}

describe('failure handling', () => {
  it('reports a failed re-run on the rules page and keeps the previous settings', async () => {
    const { user } = renderApp(flakyWorker(new Set(['redetect'])));
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detection rules'));
    const input = within(screen.getByRole('article', { name: /AUTH-001/ })).getByLabelText(
      /Failed attempts/,
    );
    await user.clear(input);
    await user.type(input, '50');
    await user.click(screen.getByRole('button', { name: 'Apply and re-run detections' }));
    expect(await screen.findByText('Detections were not re-run.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  }, 20000);

  it('shows an error instead of unfiltered data when a filtered query fails', async () => {
    const { user } = renderApp(flakyWorker(new Set(['metrics'])));
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(screen.getByRole('button', { name: /^critical/ }));
    expect(
      await screen.findByText('These figures could not be computed for the current filters.'),
    ).toBeInTheDocument();
  }, 20000);

  it('keeps charts in the zone the worker computed with when the zone changes mid-scan', async () => {
    const requests: WorkerRequest[] = [];
    const service = new AnalysisService();
    const { user } = renderApp(() => {
      const inner = createInProcessWorker(service);
      let held: WorkerRequest | null = null;
      const w: WorkerLike = {
        onmessage: null,
        onerror: null,
        onmessageerror: null,
        postMessage(m: WorkerRequest) {
          requests.push(m);
          if (m.type === 'analyze') held = m;
          else inner.postMessage(m);
        },
        terminate: () => inner.terminate(),
      };
      inner.onmessage = (e) => w.onmessage?.(e);
      (w as WorkerLike & { release: () => void }).release = () => held && inner.postMessage(held);
      (globalThis as { __release?: () => void }).__release = (
        w as WorkerLike & { release: () => void }
      ).release;
      return w;
    });
    const card = screen.getByText('Linux SSH auth log').closest('article')!;
    await user.click(within(card).getByRole('button', { name: 'Analyze sample' }));
    await user.click(screen.getByRole('button', { name: /^Local/ }));
    act(() => (globalThis as { __release?: () => void }).__release?.());
    await screen.findByRole('heading', { name: 'Overview', level: 1 }, { timeout: 15000 });
    // The scan was computed in UTC, so the local view must ask for local-time figures.
    await waitFor(() =>
      expect(requests.some((r) => r.type === 'metrics' && r.filter.timeZone === 'local')).toBe(
        true,
      ),
    );
  }, 20000);
});
