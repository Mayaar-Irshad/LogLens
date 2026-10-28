import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { WorkerLike } from '../../src/workers/analysisClient';
import type { WorkerRequest, WorkerResponse } from '../../src/workers/protocol';
import { analyzeSample, nav, renderApp } from '../helpers/app';

const tile = (label: string) => screen.getByText(label, { selector: '.kpi-label' }).parentElement!;

describe('end-to-end analysis in the UI', () => {
  it('analyzes a sample and shows real results on the overview', async () => {
    const { user } = renderApp();
    expect(nav('Overview')).toBeDisabled();
    await analyzeSample(user, 'Linux SSH auth log');
    expect(within(tile('Events analyzed')).getByText('894')).toBeInTheDocument();
    expect(within(tile('Failed logins')).getByText('280')).toBeInTheDocument();
    expect(within(tile('Failed logins')).getByText('of 374 attempts')).toBeInTheDocument();
    expect(screen.getByText('sample-auth.log')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Priority detections/ })).toBeInTheDocument();
    // The finding under the title names the highest-priority detection.
    expect(screen.getByText(/Highest priority:/)).toHaveTextContent('flagged by');
    expect(screen.getByRole('button', { name: /Review 14 open detections/ })).toBeInTheDocument();
    expect(
      screen.getAllByText(/Source IP 203\.0\.113\.50 flagged by 3 rules/).length,
    ).toBeGreaterThan(0);
  }, 20000);

  it('cross-filters every view from a chart and clears the filter', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    const allDetections = Number(within(tile('Detections')).getByText(/^\d+$/).textContent);

    const chart = screen
      .getByRole('heading', { name: 'Most active source IPs' })
      .closest('section')!;
    await user.click(within(chart).getByRole('button', { name: 'Table' }));
    const row = within(chart).getByText('203.0.113.77').closest('tr')!;
    await user.click(within(row).getByRole('button', { name: 'Apply' }));

    expect(await screen.findByText('IP: 203.0.113.77')).toBeInTheDocument();
    await waitFor(() =>
      expect(within(tile('Events analyzed')).getByText('57')).toBeInTheDocument(),
    );
    const filteredDetections = Number(within(tile('Detections')).getByText(/^\d+$/).textContent);
    expect(filteredDetections).toBeLessThan(allDetections);

    await user.click(nav('Detections'));
    const list = await screen.findByRole('region', { name: 'Detections' });
    const titles = within(list)
      .getAllByRole('button')
      .map((b) => b.textContent ?? '');
    expect(titles.length).toBe(filteredDetections);
    expect(titles.some((t) => t.includes('203.0.113.50'))).toBe(false);

    await user.click(nav('Event explorer'));
    expect(await screen.findByText('57 matching events')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Clear all filters' }));
    expect(await screen.findByText('894 matching events')).toBeInTheDocument();
  }, 20000);

  it('supports the investigation workflow: review status, notes, evidence and pivots', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    const detail = await screen.findByRole('article', { name: /flagged by/ });
    expect(within(detail).getByText('Why this was flagged')).toBeInTheDocument();
    expect(within(detail).getByText('Suggested next steps')).toBeInTheDocument();
    expect(within(detail).getByText(/Measured value/)).toBeInTheDocument();
    expect(await within(detail).findByText(/of 237$/)).toBeInTheDocument();

    await user.click(within(detail).getByRole('radio', { name: 'Reviewed' }));
    expect(within(detail).getByRole('radio', { name: 'Reviewed' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    await user.type(within(detail).getByLabelText('Analyst note'), 'Checked with deploy owner');
    expect(within(detail).getByLabelText('Analyst note')).toHaveValue('Checked with deploy owner');

    const list = screen.getByRole('region', { name: 'Detections' });
    expect(within(list).getAllByText('Reviewed').length).toBe(1);

    // Filter the list to unresolved/open only: the reviewed one disappears.
    const statusGroup = screen.getByRole('group', { name: 'Status' });
    await user.click(within(statusGroup).getByRole('checkbox', { name: 'Open' }));
    await waitFor(() =>
      expect(
        within(screen.getByRole('region', { name: 'Detections' })).queryAllByText('Reviewed'),
      ).toHaveLength(0),
    );
    await user.click(within(statusGroup).getByRole('checkbox', { name: 'Open' }));

    // Pivot from an entity to the event explorer.
    const detail2 = screen.getByRole('article', { name: /flagged by/ });
    await user.click(within(detail2).getAllByTitle('Show all events from this IP')[0]!);
    expect(await screen.findByRole('heading', { name: 'Event explorer' })).toBeInTheDocument();
    expect(screen.getByText(/^IP: /)).toBeInTheDocument();
  }, 20000);

  it('opens an event with its original line and related events', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Event explorer'));
    await screen.findByText('894 matching events');
    const table = screen.getByRole('table', { name: 'Parsed events' });
    await user.click(within(table).getAllByRole('button', { name: /Open event \d+ details/ })[1]!);
    const detail = await screen.findByRole('region', { name: /Event #1/ });
    expect(within(detail).getByText('Original log line')).toBeInTheDocument();
    expect(detail.querySelector('pre.raw-line')?.textContent).toContain('Accepted');
    expect(await within(detail).findByText(/event\(s\) with same source IP/)).toBeInTheDocument();
    await user.click(within(detail).getByRole('tab', { name: 'Same username' }));
    expect(await within(detail).findByText(/event\(s\) with same username/)).toBeInTheDocument();
    await user.click(within(detail).getByRole('button', { name: 'Close event details' }));
    expect(screen.queryByRole('region', { name: /Event #1/ })).not.toBeInTheDocument();
  }, 20000);

  it('resets all investigation state when a new scan starts', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    const detail = await screen.findByRole('article', { name: /flagged by/ });
    await user.click(within(detail).getByRole('radio', { name: 'Reviewed' }));
    await user.click(screen.getByRole('button', { name: 'New scan' }));
    // Review work exists, so New scan asks before discarding it.
    await user.click(screen.getByRole('button', { name: 'Discard and start over' }));
    expect(screen.getByRole('heading', { name: 'Data source' })).toBeInTheDocument();
    expect(nav('Detections')).toBeDisabled();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detections'));
    const list = await screen.findByRole('region', { name: 'Detections' });
    expect(within(list).queryAllByText('Reviewed')).toHaveLength(0);
  }, 30000);

  it('shows empty states when a dataset lacks the needed fields', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Web activity'));
    expect(await screen.findByText('This dataset has no web requests.')).toBeInTheDocument();
  }, 20000);

  it('re-runs detections when thresholds change', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Detection rules'));
    const rule = screen.getByRole('article', { name: /AUTH-001/ });
    expect(within(rule).getByText('Last run: 2 findings')).toBeInTheDocument();
    const input = within(rule).getByLabelText(/Failed attempts/);
    await user.clear(input);
    await user.type(input, '1000');
    await user.click(screen.getByRole('button', { name: 'Apply and re-run detections' }));
    expect(
      await within(screen.getByRole('article', { name: /AUTH-001/ })).findByText(
        'Last run: 0 findings',
      ),
    ).toBeInTheDocument();
    // Out-of-range values are flagged and cannot be applied.
    const input2 = within(screen.getByRole('article', { name: /AUTH-001/ })).getByLabelText(
      /Failed attempts/,
    );
    await user.clear(input2);
    await user.type(input2, '0');
    expect(input2).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Apply and re-run detections' })).toBeDisabled();
  }, 20000);
});

describe('input handling in the UI', () => {
  it('renders XSS-like log content as inert text', async () => {
    const { user } = renderApp();
    const payload =
      'Oct 27 10:00:00 h sshd[1]: Failed password for invalid user <img src=x onerror=alert(1)><script>alert(2)</script> from 203.0.113.5 port 22 ssh2';
    await user.click(screen.getByLabelText('Log lines to analyze'));
    await user.paste(payload);
    await user.click(screen.getByRole('button', { name: 'Inspect pasted text' }));
    expect(await screen.findByText(/Confirm format/)).toBeInTheDocument();
    expect(screen.getByLabelText('Log format')).toHaveValue('linux-auth');
    const scripts = document.querySelectorAll('script').length;
    await user.click(screen.getByRole('button', { name: 'Analyze locally' }));
    await screen.findByRole('heading', { name: 'Overview', level: 1 }, { timeout: 15000 });
    await user.click(nav('Event explorer'));
    await screen.findByText('1 matching events');
    expect(
      screen.getAllByText(/<img src=x onerror=alert\(1\)><script>alert\(2\)<\/script>/).length,
    ).toBeGreaterThan(0);
    expect(document.querySelectorAll('script').length).toBe(scripts);
    expect(document.querySelector('img[src="x"]')).toBeNull();
  }, 20000);

  it('rejects empty, oversized and compressed files before reading them', async () => {
    renderApp();
    // The picker's accept list hides .gz files, but users can choose "All files" or drag and drop.
    const user = userEvent.setup({ applyAccept: false });
    const input = screen.getByLabelText('Choose a log file');
    await user.upload(input, new File([''], 'empty.log'));
    expect(await screen.findByText(/The file is empty/)).toBeInTheDocument();
    const big = new File(['x'], 'huge.log');
    Object.defineProperty(big, 'size', { value: 500 * 1024 * 1024 });
    await user.upload(input, big);
    expect(await screen.findByText(/exceeds the 25.0 MB limit/)).toBeInTheDocument();
    await user.upload(input, new File(['x'], 'logs.tar.gz'));
    expect(await screen.findByText(/Compressed archives are not supported/)).toBeInTheDocument();
  });

  it('detects a CSV upload and proposes a field mapping', async () => {
    const { user } = renderApp();
    const csv =
      'timestamp,src_ip,user,result\n2026-10-27T10:00:00Z,192.0.2.1,alice,failure\n2026-10-27T10:00:05Z,192.0.2.1,alice,success\n';
    await user.upload(
      screen.getByLabelText('Choose a log file'),
      new File([csv], 'auth.csv', { type: 'text/csv' }),
    );
    expect(await screen.findByText(/Confirm format: auth\.csv/)).toBeInTheDocument();
    expect(screen.getByLabelText('Log format')).toHaveValue('csv');
    expect(screen.getByLabelText('Timestamp')).toHaveValue('timestamp');
    expect(screen.getByLabelText('Source IP')).toHaveValue('src_ip');
    expect(screen.getByLabelText('Username')).toHaveValue('user');
    expect(screen.getByLabelText('Outcome (success / failure)')).toHaveValue('result');
  });

  it('flags binary content and an invalid source time zone', async () => {
    const { user } = renderApp();
    await user.upload(
      screen.getByLabelText('Choose a log file'),
      new File([new Uint8Array([0, 1, 2, 0, 80, 75])], 'blob.log'),
    );
    expect(await screen.findByText(/looks binary or compressed/)).toBeInTheDocument();
    await user.click(screen.getByLabelText('Log lines to analyze'));
    await user.paste(
      'Oct 27 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2',
    );
    await user.click(screen.getByRole('button', { name: 'Inspect pasted text' }));
    const tz = await screen.findByLabelText(/Source time zone/);
    await user.clear(tz);
    await user.type(tz, 'Mars/Olympus');
    expect(screen.getByText(/Use UTC or an offset/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Analyze locally' })).toBeDisabled();
  });
});

/** A worker that records requests and lets the test decide how it responds. */
class ScriptedWorker implements WorkerLike {
  onmessage: ((e: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  onmessageerror: ((e: MessageEvent) => void) | null = null;
  requests: WorkerRequest[] = [];
  terminated = false;
  postMessage(m: WorkerRequest): void {
    this.requests.push(m);
  }
  terminate(): void {
    this.terminated = true;
  }
}

describe('worker failure handling in the UI', () => {
  it('cancels a running scan and discards everything', async () => {
    const workers: ScriptedWorker[] = [];
    const { user } = renderApp(() => {
      const w = new ScriptedWorker();
      workers.push(w);
      return w;
    });
    const card = screen.getByText('Nginx access log').closest('article')!;
    await user.click(within(card).getByRole('button', { name: 'Analyze sample' }));
    expect(await screen.findByRole('progressbar', { name: 'Scan progress' })).toBeInTheDocument();
    act(() => {
      const w = workers[0]!;
      w.onmessage?.({
        data: {
          id: w.requests[0]!.id,
          type: 'progress',
          progress: {
            phase: 'reading',
            bytesProcessed: 50,
            totalBytes: 100,
            linesProcessed: 10,
            eventsCreated: 9,
          },
        },
      } as MessageEvent<WorkerResponse>);
    });
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
    await user.click(screen.getByRole('button', { name: 'Cancel scan' }));
    expect(
      await screen.findByText(/The scan was cancelled\. No data was kept\./),
    ).toBeInTheDocument();
    expect(workers[0]!.terminated).toBe(true);
  });

  it('reports a crashed worker and recovers for the next scan', async () => {
    const workers: ScriptedWorker[] = [];
    const { user } = renderApp(() => {
      const w = new ScriptedWorker();
      workers.push(w);
      return w;
    });
    const card = screen.getByText('Linux SSH auth log').closest('article')!;
    await user.click(within(card).getByRole('button', { name: 'Analyze sample' }));
    await screen.findByRole('progressbar');
    act(() => workers[0]!.onerror?.(new Event('error')));
    expect(await screen.findByText(/analysis worker stopped unexpectedly/)).toBeInTheDocument();
    const again = screen.getByText('Linux SSH auth log').closest('article')!;
    await user.click(within(again).getByRole('button', { name: 'Analyze sample' }));
    await waitFor(() => expect(workers).toHaveLength(2));
  });

  it('shows a worker-reported error', async () => {
    const workers: ScriptedWorker[] = [];
    const { user } = renderApp(() => {
      const w = new ScriptedWorker();
      workers.push(w);
      return w;
    });
    const card = screen.getByText('Linux SSH auth log').closest('article')!;
    await user.click(within(card).getByRole('button', { name: 'Analyze sample' }));
    await screen.findByRole('progressbar');
    act(() => {
      const w = workers[0]!;
      w.onmessage?.({
        data: {
          id: w.requests[0]!.id,
          type: 'error',
          error: { code: 'input_too_large', message: 'Input is 30.0 MB, above the 25.0 MB limit.' },
        },
      } as MessageEvent<WorkerResponse>);
    });
    expect(
      await screen.findByText('Input is 30.0 MB, above the 25.0 MB limit.'),
    ).toBeInTheDocument();
  });
});
