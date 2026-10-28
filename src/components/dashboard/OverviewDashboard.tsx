import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import { assessPosture } from '../../features/detection/risk/risk';
import { byPriority, severityCounts } from '../../features/investigation/detections';
import { statusOf } from '../../features/investigation/filters';
import { formatDuration, formatShortTimestamp, formatTimestamp } from '../../utils/format';
import { SeverityDonut, TimeSeriesChart, TopBarChart } from '../charts/Charts';
import { CHART } from '../charts/chartTheme';
import { PageHeader } from '../common/Misc';
import { ActivityStrip } from './ActivityStrip';
import { MetricsUnavailable } from './MetricsUnavailable';
import { DetectionList, KpiStrip, RiskyIndicators, RulesTriggered } from './Widgets';

const n = (v: number) => v.toLocaleString('en-US');

/**
 * The overview answers one question first: what in this log needs attention?
 * The highest-priority detection is the line under the title, the detection
 * count leads the figures, and the prioritised list is the largest block.
 */
export function OverviewDashboard() {
  const { state, actions } = useApp();
  const { metrics, detections, filtered, error } = useData();
  const summary = state.summary!;
  if (!metrics || error) return <MetricsUnavailable title="Overview" error={error} />;
  const caps = summary.capabilities;
  const counts = severityCounts(detections);
  const posture = assessPosture(detections);
  const range = metrics.timeRange;
  const visibleIds = new Set(detections.map((d) => d.id));
  const entities = filtered
    ? state.entities.filter((e) => e.detectionIds.some((id) => visibleIds.has(id)))
    : state.entities;
  const riskyIps = new Set(entities.filter((e) => e.kind === 'ip').map((e) => e.value));
  const riskyUsers = new Set(entities.filter((e) => e.kind === 'user').map((e) => e.value));
  const top = [...detections].sort(byPriority)[0];
  const open = detections.filter((d) => statusOf(state.statuses, d.id) !== 'reviewed').length;
  const urgent = counts.critical + counts.high;

  return (
    <div className="view">
      <PageHeader
        title="Overview"
        description={
          top ? (
            <>
              Highest priority: <strong>{top.title}</strong> ({top.ruleId},{' '}
              {n(top.matchedEventCount)} events, from {formatTimestamp(top.start, state.timeZone)}).{' '}
              {posture.summary}
            </>
          ) : (
            <>
              No detection rule triggered for {filtered ? 'the current filters' : 'this data'} with
              the current thresholds. That is not proof nothing happened: check which rules could
              run on the Detection rules page.
            </>
          )
        }
        actions={
          detections.length > 0 ? (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                if (top) actions.dispatch({ type: 'selectDetection', id: top.id });
                actions.navigate('alerts');
              }}
            >
              Review {open} open detection{open === 1 ? '' : 's'}
            </button>
          ) : undefined
        }
      />

      <KpiStrip
        label="Key figures"
        items={[
          {
            label: 'Detections',
            value: n(detections.length),
            sub:
              urgent > 0
                ? `${counts.critical} critical · ${counts.high} high`
                : 'none critical or high',
            lead: true,
            ...(urgent > 0 ? { tone: 'neg' as const } : {}),
          },
          {
            label: 'Events analyzed',
            value: n(metrics.totalEvents),
            sub: `${n(summary.stats.rejectedRecords)} rejected · ${n(metrics.partialEvents)} partial`,
          },
          {
            label: 'Time span',
            value:
              range.start !== undefined && range.end !== undefined
                ? formatDuration(range.end - range.start)
                : '—',
            sub:
              range.start !== undefined && range.end !== undefined
                ? `ends ${formatShortTimestamp(range.end, state.timeZone)}`
                : 'no valid timestamps',
          },
          {
            label: 'Source IPs',
            value: caps.hasIps ? n(metrics.uniqueIps) : '—',
            sub: caps.hasIps ? `${riskyIps.size} in detections` : 'none in this data',
          },
          {
            label: 'Usernames',
            value: caps.hasUsers ? n(metrics.uniqueUsers) : '—',
            sub: caps.hasUsers ? `${riskyUsers.size} in detections` : 'none in this data',
          },
          {
            label: 'Failed logins',
            value: caps.hasAuth ? n(metrics.auth.failure) : '—',
            sub: caps.hasAuth ? `of ${n(metrics.auth.total)} attempts` : 'no authentication events',
            ...(caps.hasAuth && metrics.auth.failure > metrics.auth.success
              ? { tone: 'warn' as const }
              : {}),
          },
        ]}
      />

      <div className="grid grid-2-1">
        <section className="card" aria-labelledby="priority-title">
          <header className="card-header">
            <div>
              <h2 className="card-title" id="priority-title">
                Priority detections <span className="count">{detections.length}</span>
              </h2>
              <p className="card-sub">
                Leads from threshold rules, highest severity and risk first. Verify the evidence
                before drawing conclusions.
              </p>
            </div>
          </header>
          <DetectionList
            detections={detections}
            limit={6}
            emptyText="No detections for the current data, filters and thresholds."
          />
        </section>
        <SeverityDonut
          counts={counts}
          selected={state.filters.severities}
          onSelect={(s) => actions.toggleFilter('severities', s)}
          title="Severity"
          description={`${new Set(detections.map((d) => d.ruleId)).size} rules triggered`}
          extra={<RulesTriggered detections={detections} />}
        />
      </div>

      <ActivityStrip entities={entities} detections={detections} />

      <div className="grid grid-2-1">
        <TimeSeriesChart
          title="Event volume"
          description="Parsed events with a timestamp, per period."
          buckets={metrics.timeline.buckets}
          bucketMs={metrics.timeline.bucketMs}
          timeZone={state.timeZone}
          series={[{ key: 'total', label: 'Events', color: CHART.primary }]}
          stacked={false}
          onSelectBucket={(start, end) =>
            actions.setFilters({ ...state.filters, timeRange: { start, end } })
          }
        />
        <section className="card" aria-labelledby="risky-indicators">
          <header className="card-header">
            <div>
              <h2 className="card-title" id="risky-indicators">
                Indicators to investigate
              </h2>
              <p className="card-sub">Highest finding score plus 6 per additional rule.</p>
            </div>
          </header>
          <RiskyIndicators entities={entities} />
        </section>
      </div>

      <div className="grid grid-2">
        <TopBarChart
          title="Most active source IPs"
          description="Events per source IP."
          items={metrics.topIps}
          valueLabel="Events"
          highlight={riskyIps}
          selected={state.filters.sourceIps}
          onSelect={(ip) => actions.toggleFilter('sourceIps', ip)}
          emptyText="No source IP addresses in the current data."
        />
        <TopBarChart
          title="Most targeted usernames"
          description="Failed logins per account."
          items={metrics.auth.topFailedUsers}
          valueLabel="Failed logins"
          highlight={riskyUsers}
          selected={state.filters.usernames}
          onSelect={(u) => actions.toggleFilter('usernames', u)}
          emptyText={
            caps.hasUsers
              ? 'No failed logins with a username in the current data.'
              : 'This data has no usernames.'
          }
        />
      </div>
    </div>
  );
}
