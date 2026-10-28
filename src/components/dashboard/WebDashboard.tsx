import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import { formatBytes, formatPercent } from '../../utils/format';
import { ColumnChart, TimeSeriesChart, TopBarChart } from '../charts/Charts';
import { CHART } from '../charts/chartTheme';
import { STANDARD_METHODS } from '../../features/detection/rules/webSignatures';
import { EmptyState, PageHeader } from '../common/Misc';
import { MetricsUnavailable } from './MetricsUnavailable';
import { DetectionGroup, KpiStrip } from './Widgets';

const classColor = (code: string): string => CHART.status[`${code.charAt(0)}xx`] ?? CHART.muted;

export function WebDashboard() {
  const { state, actions } = useApp();
  const { metrics, detections, error } = useData();
  const summary = state.summary!;
  if (!summary.capabilities.hasWeb) {
    return (
      <div className="view">
        <PageHeader title="Web activity" />
        <EmptyState title="This dataset has no web requests.">
          Web charts need Apache/Nginx access logs, or CSV/JSON records with a mapped HTTP method,
          path or status code.
        </EmptyState>
      </div>
    );
  }
  if (!metrics || error) return <MetricsUnavailable title="Web activity" error={error} />;
  const w = metrics.web;
  const cls = (k: string) => w.statusClasses.find((c) => c.key === k)?.count ?? 0;
  const errorPath = w.topErrorPaths[0];
  const webDetections = detections.filter((d) => d.ruleCategory === 'web');
  const riskyIps = new Set(
    state.entities
      .filter(
        (e) => e.kind === 'ip' && e.detectionIds.some((id) => detections.some((d) => d.id === id)),
      )
      .map((e) => e.value),
  );
  const setRange = (start: number, end: number) =>
    actions.setFilters({ ...state.filters, timeRange: { start, end } });

  return (
    <div className="view">
      <PageHeader
        title="Web activity"
        description={
          <>
            {w.total.toLocaleString('en-US')} requests from{' '}
            {w.uniqueClients.toLocaleString('en-US')} clients: {cls('4xx').toLocaleString('en-US')}{' '}
            client errors and {cls('5xx').toLocaleString('en-US')} server errors
            {errorPath && (
              <>
                ; <span className="mono">{errorPath.key}</span> produced the most errors (
                {errorPath.count.toLocaleString('en-US')})
              </>
            )}
            . Error responses and unusual requests are context, not proof of an attack.
          </>
        }
      />
      <KpiStrip
        label="Web figures"
        items={[
          {
            label: 'Requests',
            value: w.total.toLocaleString('en-US'),
            sub: `${formatBytes(w.bytes)} sent`,
            lead: true,
          },
          {
            label: 'Clients',
            value: w.uniqueClients.toLocaleString('en-US'),
            sub: `${riskyIps.size} in detections`,
          },
          { label: 'Distinct paths', value: w.uniquePaths.toLocaleString('en-US') },
          {
            label: 'Client errors (4xx)',
            value: cls('4xx').toLocaleString('en-US'),
            sub: `${formatPercent(cls('4xx'), w.total)} of requests`,
            ...(cls('4xx') > 0 ? { tone: 'warn' as const } : {}),
          },
          {
            label: 'Server errors (5xx)',
            value: cls('5xx').toLocaleString('en-US'),
            sub: `${formatPercent(cls('5xx'), w.total)} of requests`,
            ...(cls('5xx') > 0 ? { tone: 'neg' as const } : {}),
          },
          {
            label: 'Detections',
            value: webDetections.length.toLocaleString('en-US'),
            sub: 'web rules',
          },
        ]}
      />

      <div className="grid grid-2-1">
        <TimeSeriesChart
          title="Requests over time by status class"
          buckets={metrics.timeline.buckets}
          bucketMs={metrics.timeline.bucketMs}
          timeZone={state.timeZone}
          series={[
            { key: 'web2xx', label: '1xx/2xx', color: CHART.status['2xx']! },
            { key: 'web3xx', label: '3xx', color: CHART.status['3xx']! },
            { key: 'web4xx', label: '4xx', color: CHART.status['4xx']! },
            { key: 'web5xx', label: '5xx', color: CHART.status['5xx']! },
          ]}
          stacked
          onSelectBucket={setRange}
          emptyText="No timestamped web requests for the current filters."
        />
        <ColumnChart
          title="HTTP methods"
          items={w.methods}
          colorFor={(m) => (STANDARD_METHODS.has(m) ? CHART.neutral : CHART.status['4xx']!)}
          legend={[
            { label: 'Standard', color: CHART.neutral },
            { label: 'Non-standard', color: CHART.status['4xx']! },
          ]}
          valueLabel="Requests"
          selected={state.filters.httpMethods}
          onSelect={(m) => actions.toggleFilter('httpMethods', m)}
          emptyText="No HTTP methods for the current filters."
        />
      </div>

      <div className="grid grid-2">
        <TopBarChart
          title="Most active clients"
          items={w.topClients}
          highlight={riskyIps}
          valueLabel="Requests"
          selected={state.filters.sourceIps}
          onSelect={(ip) => actions.toggleFilter('sourceIps', ip)}
          emptyText="No client addresses for the current filters."
        />
        <TopBarChart
          title="Most requested paths"
          items={w.topPaths}
          valueLabel="Requests"
          selected={state.filters.paths}
          onSelect={(p) => actions.toggleFilter('paths', p)}
          emptyText="No request paths for the current filters."
        />
        <ColumnChart
          legend={[
            { label: '2xx/3xx', color: CHART.status['2xx']! },
            { label: '4xx', color: CHART.status['4xx']! },
            { label: '5xx', color: CHART.status['5xx']! },
          ]}
          title="HTTP status codes"
          items={w.statusCodes}
          colorFor={classColor}
          valueLabel="Requests"
          selected={state.filters.httpStatuses.map(String)}
          onSelect={(code) => actions.toggleFilter('httpStatuses', Number(code))}
          emptyText="No status codes for the current filters."
        />
        <TopBarChart
          title="Paths producing errors"
          description="Requests answered with status 400 or higher."
          items={w.topErrorPaths}
          valueLabel="Error responses"
          color={CHART.status['4xx']}
          selected={state.filters.paths}
          onSelect={(p) => actions.toggleFilter('paths', p)}
          emptyText="No error responses for the current filters."
        />
      </div>

      <div className="group-flow">
        <DetectionGroup
          title="Reconnaissance and probing"
          description="Sensitive paths (WEB-003), path probing (WEB-004) and scanner user agents (WEB-009)."
          ruleIds={['WEB-003', 'WEB-004', 'WEB-009']}
          detections={detections}
        />
        <DetectionGroup
          title="Suspicious requests"
          description="Attack signatures in requests (WEB-008) and unusual HTTP methods or malformed request lines (WEB-005)."
          ruleIds={['WEB-008', 'WEB-005']}
          detections={detections}
        />
        <DetectionGroup
          title="Error spikes"
          description="Bursts of 4xx (WEB-001) or 5xx (WEB-002) responses and repeated failing requests (WEB-007)."
          ruleIds={['WEB-001', 'WEB-002', 'WEB-007']}
          detections={detections}
        />
        <DetectionGroup
          title="High request rates"
          description="Excessive request volume from one client (WEB-006)."
          ruleIds={['WEB-006']}
          detections={detections}
        />
      </div>
    </div>
  );
}
