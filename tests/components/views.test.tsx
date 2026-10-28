import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { analyzeSample, nav, renderApp } from '../helpers/app';

const tile = (label: string) => screen.getByText(label, { selector: '.kpi-label' }).parentElement!;

/** Capture downloads instead of letting jsdom navigate. */
function captureDownloads() {
  const files: Array<{ name: string; blob: Blob }> = [];
  let pending: Blob | null = null;
  Object.assign(URL, {
    createObjectURL: (b: Blob) => {
      pending = b;
      return 'blob:test';
    },
    revokeObjectURL: () => undefined,
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    if (pending) files.push({ name: this.download, blob: pending });
    pending = null;
  });
  return files;
}

describe('dashboards', () => {
  it('renders the authentication dashboard from real counts', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Authentication'));
    expect(within(tile('Attempts')).getByText('374')).toBeInTheDocument();
    expect(within(tile('Failed logins')).getByText('280')).toBeInTheDocument();
    expect(within(tile('Failed logins')).getByText('75% of attempts')).toBeInTheDocument();
    expect(
      screen.getByRole('region', { name: 'Success after repeated failures' }),
    ).toHaveTextContent('"deploy" from 203.0.113.50');

    // Table alternative for a time-series chart lists real buckets.
    const chart = screen
      .getByRole('heading', { name: 'Failed vs successful logins' })
      .closest('section')!;
    await user.click(within(chart).getByRole('button', { name: 'Table' }));
    const rows = within(chart).getAllByRole('row');
    expect(rows.length).toBeGreaterThan(5);
    expect(within(chart).getByRole('columnheader', { name: 'Failed' })).toBeInTheDocument();

    // Hour-of-day table and filtering by username from the top-N table.
    const users = screen
      .getByRole('heading', { name: 'Usernames targeted by failed logins' })
      .closest('section')!;
    await user.click(within(users).getByRole('button', { name: 'Table' }));
    await user.click(
      within(within(users).getByText('root').closest('tr')!).getByRole('button', { name: 'Apply' }),
    );
    expect(await screen.findByText('User: root')).toBeInTheDocument();
    await waitFor(() =>
      expect(within(tile('Successful logins')).getByText('0')).toBeInTheDocument(),
    );
  }, 20000);

  it('renders the web dashboard and reports no auth data for web logs', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Nginx access log');
    await user.click(nav('Web activity'));
    expect(screen.getByRole('heading', { name: 'Web activity', level: 1 })).toBeInTheDocument();
    expect(within(tile('Requests')).getByText('10,590')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Reconnaissance and probing' })).toHaveTextContent(
      'Sensitive file served to 203.0.113.9',
    );
    const codes = screen.getByRole('heading', { name: 'HTTP status codes' }).closest('section')!;
    await user.click(within(codes).getByRole('button', { name: 'Table' }));
    expect(within(codes).getByRole('cell', { name: '502' })).toBeInTheDocument();
    await user.click(nav('Authentication'));
    expect(screen.getByText(/no authentication attempts/)).toBeInTheDocument();
  }, 30000);
});

describe('data source report', () => {
  it('shows parsing statistics, warnings and inspectable rejected records', async () => {
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Data source'));
    const report = screen.getByRole('region', { name: 'Parsing report' });
    expect(within(report).getByText('Rejected').nextElementSibling).toHaveTextContent('2');
    expect(within(report).getByText(/Syslog timestamps do not include a year/)).toBeInTheDocument();
    await user.click(within(report).getByText(/Inspect rejected records/));
    expect(within(report).getAllByRole('cell', { name: 'Unrecognized format' })).toHaveLength(2);
  }, 20000);
});

describe('reports and export', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it('downloads a JSON report without raw lines by default and with them on request', async () => {
    const files = captureDownloads();
    const { user } = renderApp();
    await analyzeSample(user, 'Linux SSH auth log');
    await user.click(nav('Report & export'));
    await user.type(
      screen.getByRole('textbox', { name: 'Investigation summary note' }),
      'Initial triage',
    );
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    await screen.findByText(/Report generated with \d+ detection/);
    expect(files[0]!.name).toMatch(/^loglens-report-sample-auth-\d{8}-\d{6}Z\.json$/);
    const report = JSON.parse(await files[0]!.blob.text()) as {
      application: { name: string; version: string };
      detections: Array<{ eventReferences: Array<Record<string, unknown>> }>;
      investigationNote: string;
      privacy: { rawLogLinesIncluded: boolean };
    };
    expect(report.application).toEqual({ name: 'LogLens', version: '1.0.0' });
    expect(report.investigationNote).toBe('Initial triage');
    expect(report.privacy.rawLogLinesIncluded).toBe(false);
    expect(report.detections[0]!.eventReferences.length).toBeGreaterThan(0);
    expect(report.detections[0]!.eventReferences[0]).not.toHaveProperty('rawLogLine');

    await user.click(screen.getByLabelText('Include original log lines for referenced events'));
    expect(screen.getByText(/can contain sensitive data/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    await waitFor(() => expect(files).toHaveLength(2));
    const withRaw = JSON.parse(await files[1]!.blob.text()) as {
      detections: Array<{ eventReferences: Array<{ rawLogLine?: string }> }>;
    };
    expect(withRaw.detections[0]!.eventReferences[0]!.rawLogLine).toContain('sshd');
  }, 20000);

  it('exports filtered events as CSV with formula injection neutralized', async () => {
    const files = captureDownloads();
    const { user } = renderApp();
    await analyzeSample(user, 'Web requests CSV');
    await user.click(nav('Report & export'));
    await user.click(screen.getByRole('button', { name: /Download events CSV/ }));
    await screen.findByText(/rows exported/);
    const csv = await files[0]!.blob.text();
    expect(files[0]!.name).toMatch(/^loglens-events-sample-web-requests-.*\.csv$/);
    expect(csv.split('\r\n')[0]).toContain('"event_id"');
    expect(csv).toContain(`"'=HYPERLINK(""https://example.test"",""click"")"`);
    expect(csv).not.toContain('raw_log_line');
  }, 20000);
});
