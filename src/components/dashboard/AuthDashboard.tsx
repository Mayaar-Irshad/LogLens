import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import { formatPercent } from '../../utils/format';
import { HourlyChart, TimeSeriesChart, TopBarChart } from '../charts/Charts';
import { CHART } from '../charts/chartTheme';
import { EmptyState, PageHeader } from '../common/Misc';
import { MetricsUnavailable } from './MetricsUnavailable';
import { DetectionGroup, KpiStrip } from './Widgets';

export function AuthDashboard() {
  const { state, actions } = useApp();
  const { metrics, detections, error } = useData();
  const summary = state.summary!;
  if (!summary.capabilities.hasAuth) {
    return (
      <div className="view">
        <PageHeader title="Authentication" />
        <EmptyState title="This dataset has no authentication attempts with a success or failure outcome.">
          Authentication charts need records such as sshd “Failed/Accepted password” lines, or
          CSV/JSON records with a mapped outcome or an event type such as “login_failed”. Re-scan
          with a field mapping that includes Outcome or Event type.
        </EmptyState>
      </div>
    );
  }
  if (!metrics || error) return <MetricsUnavailable title="Authentication" error={error} />;
  const a = metrics.auth;
  const topIp = a.topFailedIps[0];
  const topUser = a.topFailedUsers[0];
  const authDetections = detections.filter((d) => d.ruleCategory === 'authentication');
  const setRange = (start: number, end: number) =>
    actions.setFilters({ ...state.filters, timeRange: { start, end } });

  return (
    <div className="view">
      <PageHeader
        title="Authentication"
        description={
          a.failure > 0 ? (
            <>
              {a.failure.toLocaleString('en-US')} of {a.total.toLocaleString('en-US')} login
              attempts failed ({formatPercent(a.failure, a.total)}).
              {topIp && (
                <>
                  {' '}
                  <span className="mono">{topIp.key}</span> accounts for{' '}
                  {topIp.count.toLocaleString('en-US')} of them
                </>
              )}
              {topUser && (
                <>
                  ; the most targeted account is <span className="mono">{topUser.key}</span> (
                  {topUser.count.toLocaleString('en-US')})
                </>
              )}
              .
            </>
          ) : (
            `${a.total.toLocaleString('en-US')} login attempts, none failed.`
          )
        }
      />
      <KpiStrip
        label="Authentication figures"
        items={[
          {
            label: 'Failed logins',
            value: a.failure.toLocaleString('en-US'),
            sub: `${formatPercent(a.failure, a.total)} of attempts`,
            lead: true,
            ...(a.failure > a.success ? { tone: 'neg' as const } : {}),
          },
          {
            label: 'Successful logins',
            value: a.success.toLocaleString('en-US'),
            sub: `${formatPercent(a.success, a.total)} of attempts`,
          },
          {
            label: 'Attempts',
            value: a.total.toLocaleString('en-US'),
            sub: 'with a known outcome',
          },
          {
            label: 'Against non-existent accounts',
            value: a.invalidUserAttempts.toLocaleString('en-US'),
            sub: 'failed attempts, invalid user',
          },
          {
            label: 'Detections',
            value: authDetections.length.toLocaleString('en-US'),
            sub: 'authentication rules',
          },
        ]}
      />

      <div className="grid grid-2-1">
        <TimeSeriesChart
          title="Failed vs successful logins"
          buckets={metrics.timeline.buckets}
          bucketMs={metrics.timeline.bucketMs}
          timeZone={state.timeZone}
          series={[
            { key: 'authSuccess', label: 'Successful', color: CHART.success },
            { key: 'authFailure', label: 'Failed', color: CHART.failure },
          ]}
          stacked
          onSelectBucket={setRange}
          emptyText="No timestamped authentication attempts for the current filters."
        />
        <HourlyChart
          hourly={metrics.hourly}
          series={[
            { key: 'authSuccess', label: 'Successful', color: CHART.success },
            { key: 'authFailure', label: 'Failed', color: CHART.failure },
          ]}
          timeZone={state.timeZone}
          selected={state.filters.hours}
          onSelectHour={(h) => actions.toggleFilter('hours', h)}
          title="Logins by hour of day"
        />
      </div>

      <div className="grid grid-2">
        <TopBarChart
          title="Usernames targeted by failed logins"
          items={a.topFailedUsers}
          valueLabel="Failed logins"
          color={CHART.failure}
          selected={state.filters.usernames}
          onSelect={(u) => actions.toggleFilter('usernames', u)}
          emptyText="No failed logins with a username for the current filters."
        />
        <TopBarChart
          title="Source IPs with failed logins"
          items={a.topFailedIps}
          valueLabel="Failed logins"
          color={CHART.failure}
          selected={state.filters.sourceIps}
          onSelect={(ip) => actions.toggleFilter('sourceIps', ip)}
          emptyText="No failed logins with a source IP for the current filters."
        />
      </div>

      <div className="group-flow">
        <DetectionGroup
          title="Possible brute force"
          description="Many failures from one source (AUTH-001) or unusually high login volume (AUTH-006)."
          ruleIds={['AUTH-001', 'AUTH-006']}
          detections={detections}
        />
        <DetectionGroup
          title="Possible password spraying"
          description="Few attempts across many accounts from one source (AUTH-003), across sources (AUTH-005), or non-existent usernames (AUTH-007)."
          ruleIds={['AUTH-003', 'AUTH-005', 'AUTH-007']}
          detections={detections}
        />
        <DetectionGroup
          title="Success after repeated failures"
          description="A successful login preceded by failures from the same IP or for the same account (AUTH-004). Verify with the account owner."
          ruleIds={['AUTH-004']}
          detections={detections}
        />
        <DetectionGroup
          title="Repeated failures against one account"
          description="Many failures for a single username from any source (AUTH-002)."
          ruleIds={['AUTH-002']}
          detections={detections}
        />
      </div>
    </div>
  );
}
