import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { ReactNode } from 'react';
import type { CountItem, DisplayTimeZone, TimeBucket } from '../../types/analytics';
import type { Severity } from '../../types/detection';
import type { AlertPoint } from '../../features/investigation/detections';
import { formatAxisTime, formatTimestamp } from '../../utils/format';
import { truncate } from '../../utils/text';
import { ChartCard } from './ChartCard';
import { TooltipBox } from './ChartTooltip';
import { payloadOf, type RechartsTooltipProps } from './chartUtils';
import { axisProps, CHART, SEVERITY_COLORS } from './chartTheme';

const HEIGHT = 220;
const CURSOR_FILL = { fill: 'rgba(255,255,255,0.04)' };

/** Index of the hovered/clicked datum from a Recharts chart-level event. */
function activeIndex(state: unknown): number | null {
  if (typeof state !== 'object' || state === null) return null;
  const raw =
    (state as { activeTooltipIndex?: unknown; activeIndex?: unknown }).activeTooltipIndex ??
    (state as { activeIndex?: unknown }).activeIndex;
  const n = Number(raw);
  return raw === null || raw === undefined || !Number.isInteger(n) ? null : n;
}

const dimmed = (selected: readonly unknown[], key: unknown): number =>
  selected.length === 0 || selected.includes(key) ? 1 : 0.3;

/** The keyboard-accessible way to filter from a chart: a button in its table view. */
function filterColumn<T>(label: string, onPick: (row: T) => void, isOn?: (row: T) => boolean) {
  return {
    header: 'Filter',
    cell: (row: T) => (
      <button type="button" className="btn btn-sm btn-ghost" onClick={() => onPick(row)}>
        {isOn?.(row) ? 'Remove' : label}
      </button>
    ),
  };
}

export function Legend({ items }: { items: Array<{ label: string; color: string }> }) {
  return (
    <ul className="legend">
      {items.map((i) => (
        <li key={i.label}>
          <span className="swatch" style={{ background: i.color }} aria-hidden="true" />
          {i.label}
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- time series

export interface SeriesSpec {
  key: keyof TimeBucket;
  label: string;
  color: string;
}

export function TimeSeriesChart({
  title,
  description,
  buckets,
  bucketMs,
  timeZone,
  series,
  stacked,
  onSelectBucket,
  emptyText = 'No timestamped events for the current filters.',
}: {
  title: string;
  description?: string;
  buckets: TimeBucket[];
  bucketMs: number;
  timeZone: DisplayTimeZone;
  series: SeriesSpec[];
  stacked: boolean;
  onSelectBucket?: (start: number, end: number) => void;
  emptyText?: string;
}) {
  const valueOf = (b: TimeBucket) => series.reduce((x, sp) => x + Number(b[sp.key]), 0);
  const total = buckets.reduce((s, b) => s + valueOf(b), 0);
  const span = buckets.length > 0 ? buckets[buckets.length - 1]!.t - buckets[0]!.t : 0;
  const tick = (t: number) => formatAxisTime(t, timeZone, span);
  const peak = buckets.reduce<TimeBucket | null>(
    (best, b) => (!best || valueOf(b) > valueOf(best) ? b : best),
    null,
  );
  const minutes = Math.round(bucketMs / 60000);
  const summary = `${title}: ${total.toLocaleString('en-US')} events in ${buckets.length} buckets of ${minutes} minutes${peak ? `, peak ${valueOf(peak).toLocaleString('en-US')} at ${formatTimestamp(peak.t, timeZone)}` : ''}.`;
  const select = (state: unknown) => {
    const i = activeIndex(state);
    const b = i === null ? undefined : buckets[i];
    if (b && onSelectBucket) onSelectBucket(b.t, b.t + bucketMs - 1);
  };
  const tooltip = (props: RechartsTooltipProps<TimeBucket>) => {
    const b = payloadOf(props);
    if (!b) return null;
    return (
      <TooltipBox
        title={`${formatTimestamp(b.t, timeZone)} · ${minutes} min`}
        rows={series.map((s) => ({ label: s.label, value: Number(b[s.key]), color: s.color }))}
      />
    );
  };
  const header =
    series.length > 1 ? (
      <Legend items={[...series].reverse().map((s) => ({ label: s.label, color: s.color }))} />
    ) : undefined;
  return (
    <ChartCard
      title={title}
      fill={HEIGHT}
      {...(description ? { description } : {})}
      {...(header ? { headerExtra: header } : {})}
      summary={summary}
      empty={total === 0}
      emptyText={emptyText}
      rows={buckets.filter((b) => valueOf(b) > 0)}
      columns={[
        { header: 'Bucket start', cell: (b) => formatTimestamp(b.t, timeZone) },
        ...series.map((s) => ({
          header: s.label,
          cell: (b: TimeBucket) => Number(b[s.key]).toLocaleString('en-US'),
          numeric: true,
        })),
        ...(onSelectBucket
          ? [
              filterColumn<TimeBucket>('Filter to period', (b) =>
                onSelectBucket(b.t, b.t + bucketMs - 1),
              ),
            ]
          : []),
      ]}
      {...(onSelectBucket ? { hint: 'Select a period to filter every view to it.' } : {})}
    >
      <ResponsiveContainer width="100%" height="100%">
        {stacked ? (
          <BarChart
            data={buckets}
            onClick={select}
            barCategoryGap={1}
            margin={{ top: 8, right: 4, bottom: 0, left: -8 }}
          >
            <CartesianGrid stroke={CHART.grid} vertical={false} />
            <XAxis dataKey="t" tickFormatter={tick} minTickGap={48} {...axisProps} />
            <YAxis allowDecimals={false} width={52} {...axisProps} />
            <Tooltip content={tooltip} cursor={CURSOR_FILL} isAnimationActive={false} />
            {series.map((s) => (
              <Bar
                key={String(s.key)}
                dataKey={s.key}
                name={s.label}
                stackId="a"
                fill={s.color}
                stroke={CHART.surface}
                strokeWidth={1}
                isAnimationActive={false}
                cursor={onSelectBucket ? 'pointer' : undefined}
              />
            ))}
          </BarChart>
        ) : (
          <LineChart
            data={buckets}
            onClick={select}
            margin={{ top: 8, right: 8, bottom: 0, left: -8 }}
          >
            <CartesianGrid stroke={CHART.grid} vertical={false} />
            <XAxis dataKey="t" tickFormatter={tick} minTickGap={48} {...axisProps} />
            <YAxis allowDecimals={false} width={52} {...axisProps} />
            <Tooltip
              content={tooltip}
              cursor={{ stroke: CHART.muted, strokeDasharray: '3 3' }}
              isAnimationActive={false}
            />
            {series.map((s) => (
              <Line
                key={String(s.key)}
                type="linear"
                dataKey={s.key}
                name={s.label}
                stroke={s.color}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, stroke: CHART.surface, strokeWidth: 2 }}
                isAnimationActive={false}
              />
            ))}
          </LineChart>
        )}
      </ResponsiveContainer>
    </ChartCard>
  );
}

// ---------------------------------------------------------------- top-N bars

export function TopBarChart({
  title,
  description,
  items,
  valueLabel,
  onSelect,
  selected = [],
  emptyText,
  color = CHART.neutral,
  highlight,
  highlightLabel = 'Subject of a detection',
  formatKey = (k) => k,
}: {
  title: string;
  description?: string;
  items: CountItem[];
  valueLabel: string;
  onSelect?: (key: string) => void;
  selected?: readonly string[];
  emptyText: string;
  color?: string;
  /** Keys drawn in the risk colour (for example IPs that detections are about). */
  highlight?: ReadonlySet<string>;
  highlightLabel?: string;
  formatKey?: (key: string) => string;
}) {
  const data = items.map((i) => ({ ...i, label: truncate(formatKey(i.key), 26) }));
  const isRisk = (key: string) => highlight?.has(key) ?? false;
  const anyRisk = items.some((i) => isRisk(i.key));
  const top = items[0];
  const summary = top
    ? `${title}: ${items.length} entries; highest is ${formatKey(top.key)} with ${top.count.toLocaleString('en-US')} ${valueLabel.toLowerCase()}.`
    : `${title}: no data.`;
  const tooltip = (props: RechartsTooltipProps<CountItem>) => {
    const d = payloadOf(props);
    return d ? (
      <TooltipBox
        title={formatKey(d.key)}
        rows={[
          { label: valueLabel, value: d.count, color: isRisk(d.key) ? CHART.risk : color },
          ...(isRisk(d.key) ? [{ label: highlightLabel, value: 'yes' }] : []),
        ]}
      />
    ) : null;
  };
  return (
    <ChartCard
      title={title}
      {...(description ? { description } : {})}
      {...(anyRisk
        ? {
            headerExtra: (
              <Legend
                items={[
                  { label: highlightLabel, color: CHART.risk },
                  { label: 'Other', color },
                ]}
              />
            ),
          }
        : {})}
      summary={summary}
      empty={items.length === 0}
      emptyText={emptyText}
      rows={items}
      columns={[
        { header: 'Value', cell: (r) => <span className="mono">{formatKey(r.key)}</span> },
        ...(highlight
          ? [{ header: highlightLabel, cell: (r: CountItem) => (isRisk(r.key) ? 'yes' : '—') }]
          : []),
        { header: valueLabel, cell: (r) => r.count.toLocaleString('en-US'), numeric: true },
        ...(onSelect
          ? [
              {
                header: 'Filter',
                cell: (r: CountItem) => (
                  <button
                    type="button"
                    className="btn btn-sm btn-ghost"
                    onClick={() => onSelect(r.key)}
                  >
                    {selected.includes(r.key) ? 'Remove' : 'Apply'}
                  </button>
                ),
              },
            ]
          : []),
      ]}
      {...(onSelect ? { hint: 'Select a bar to filter every view by that value.' } : {})}
    >
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 26 + 28)}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 40, bottom: 0, left: 4 }}
          barCategoryGap={5}
        >
          <CartesianGrid stroke={CHART.grid} horizontal={false} />
          <XAxis type="number" allowDecimals={false} {...axisProps} />
          <YAxis
            type="category"
            dataKey="label"
            width={168}
            {...axisProps}
            tick={{ fill: CHART.text, fontSize: 12 }}
            interval={0}
          />
          <Tooltip content={tooltip} cursor={CURSOR_FILL} isAnimationActive={false} />
          <Bar
            dataKey="count"
            name={valueLabel}
            radius={[0, 2, 2, 0]}
            isAnimationActive={false}
            label={{ position: 'right', fill: CHART.muted, fontSize: 11 }}
            onClick={(_: unknown, index: number) => {
              const item = items[index];
              if (item && onSelect) onSelect(item.key);
            }}
            cursor={onSelect ? 'pointer' : undefined}
          >
            {data.map((d) => (
              <Cell
                key={d.key}
                fill={isRisk(d.key) ? CHART.risk : color}
                fillOpacity={dimmed(selected, d.key)}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

// ---------------------------------------------------------------- categorical columns

export function ColumnChart({
  title,
  description,
  items,
  colorFor,
  valueLabel,
  onSelect,
  selected = [],
  emptyText,
  legend,
}: {
  title: string;
  description?: string;
  items: CountItem[];
  colorFor: (key: string) => string;
  valueLabel: string;
  onSelect?: (key: string) => void;
  selected?: readonly string[];
  emptyText: string;
  legend?: Array<{ label: string; color: string }>;
}) {
  const total = items.reduce((s, i) => s + i.count, 0);
  const share = (n: number) => `${((n / Math.max(1, total)) * 100).toFixed(1)}%`;
  const tooltip = (props: RechartsTooltipProps<CountItem>) => {
    const d = payloadOf(props);
    return d ? (
      <TooltipBox
        title={d.key}
        rows={[
          { label: valueLabel, value: d.count, color: colorFor(d.key) },
          { label: 'Share', value: share(d.count) },
        ]}
      />
    ) : null;
  };
  return (
    <ChartCard
      title={title}
      fill={HEIGHT}
      {...(description ? { description } : {})}
      {...(legend ? { headerExtra: <Legend items={legend} /> } : {})}
      summary={`${title}: ${items.map((i) => `${i.key} ${i.count}`).join(', ')}.`}
      empty={items.length === 0}
      emptyText={emptyText}
      rows={items}
      columns={[
        { header: 'Value', cell: (r) => r.key },
        { header: valueLabel, cell: (r) => r.count.toLocaleString('en-US'), numeric: true },
        { header: 'Share', cell: (r) => share(r.count), numeric: true },
        ...(onSelect
          ? [
              filterColumn<CountItem>(
                'Apply',
                (r) => onSelect(r.key),
                (r) => selected.includes(r.key),
              ),
            ]
          : []),
      ]}
      {...(onSelect ? { hint: 'Select a column to filter by that value.' } : {})}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={items}
          margin={{ top: 18, right: 4, bottom: 0, left: -8 }}
          barCategoryGap="20%"
        >
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis dataKey="key" interval={0} {...axisProps} />
          <YAxis allowDecimals={false} width={56} {...axisProps} />
          <Tooltip content={tooltip} cursor={CURSOR_FILL} isAnimationActive={false} />
          <Bar
            dataKey="count"
            name={valueLabel}
            radius={[2, 2, 0, 0]}
            isAnimationActive={false}
            label={{ position: 'top', fill: CHART.muted, fontSize: 11 }}
            onClick={(_: unknown, index: number) => {
              const item = items[index];
              if (item && onSelect) onSelect(item.key);
            }}
            cursor={onSelect ? 'pointer' : undefined}
          >
            {items.map((d) => (
              <Cell key={d.key} fill={colorFor(d.key)} fillOpacity={dimmed(selected, d.key)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

// ---------------------------------------------------------------- severity ring

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** A thin ring with its legend as a table of values; each row filters by severity. */
export function SeverityDonut({
  counts,
  onSelect,
  selected = [],
  title = 'Findings by severity',
  description,
  extra,
}: {
  counts: Record<Severity, number>;
  onSelect?: (s: Severity) => void;
  selected?: readonly Severity[];
  title?: string;
  description?: string;
  /** Related content shown under the ring (for example the rules behind the counts). */
  extra?: ReactNode;
}) {
  const data = SEVERITY_ORDER.map((s) => ({ key: s, count: counts[s] })).filter((d) => d.count > 0);
  const total = data.reduce((s, d) => s + d.count, 0);
  return (
    <ChartCard
      title={title}
      {...(description ? { description } : {})}
      summary={`${title}: ${data.map((d) => `${d.count} ${d.key}`).join(', ') || 'none'}.`}
      empty={total === 0}
      emptyText="No detections for the current filters."
      rows={data}
      columns={[
        { header: 'Severity', cell: (r) => r.key },
        { header: 'Detections', cell: (r) => r.count, numeric: true },
      ]}
    >
      <div className="ring-wrap">
        <div className="donut-wrap">
          <ResponsiveContainer width="100%" height={168}>
            <PieChart>
              <Pie
                data={data}
                dataKey="count"
                nameKey="key"
                innerRadius={70}
                outerRadius={80}
                paddingAngle={2}
                stroke="none"
                startAngle={90}
                endAngle={-270}
                isAnimationActive={false}
                onClick={(_: unknown, index: number) => {
                  const d = data[index];
                  if (d && onSelect) onSelect(d.key);
                }}
                cursor={onSelect ? 'pointer' : undefined}
              >
                {data.map((d) => (
                  <Cell
                    key={d.key}
                    fill={SEVERITY_COLORS[d.key]}
                    fillOpacity={dimmed(selected, d.key)}
                  />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center" aria-hidden="true">
            <span className="donut-total">{total}</span>
            <span className="muted small">detections</span>
          </div>
        </div>
        <ul className="donut-legend" aria-label="Filter by severity">
          {data.map((d) => (
            <li key={d.key} className={selected.includes(d.key) ? 'selected' : undefined}>
              {onSelect ? (
                <button
                  type="button"
                  aria-pressed={selected.includes(d.key)}
                  onClick={() => onSelect(d.key)}
                >
                  <span
                    className="swatch"
                    style={{ background: SEVERITY_COLORS[d.key] }}
                    aria-hidden="true"
                  />
                  <span>{d.key}</span>
                  <span className="legend-value">{d.count}</span>
                </button>
              ) : (
                <>
                  <span
                    className="swatch"
                    style={{ background: SEVERITY_COLORS[d.key] }}
                    aria-hidden="true"
                  />
                  <span>{d.key}</span>
                  <span className="legend-value">{d.count}</span>
                </>
              )}
            </li>
          ))}
        </ul>
      </div>
      {extra}
    </ChartCard>
  );
}

// ---------------------------------------------------------------- hourly

export function HourlyChart({
  hourly,
  series,
  timeZone,
  onSelectHour,
  selected = [],
  title = 'Activity by hour of day',
}: {
  hourly: Array<{
    hour: number;
    total: number;
    authFailure: number;
    authSuccess: number;
    web: number;
  }>;
  series: Array<{
    key: 'total' | 'authFailure' | 'authSuccess' | 'web';
    label: string;
    color: string;
  }>;
  timeZone: DisplayTimeZone;
  onSelectHour?: (hour: number) => void;
  selected?: readonly number[];
  title?: string;
}) {
  const total = hourly.reduce((s, h) => s + series.reduce((x, sp) => x + h[sp.key], 0), 0);
  const zone = timeZone === 'UTC' ? 'UTC' : 'local time';
  const data = hourly.map((h) => ({ ...h, label: `${String(h.hour).padStart(2, '0')}` }));
  const tooltip = (props: RechartsTooltipProps<(typeof data)[number]>) => {
    const d = payloadOf(props);
    return d ? (
      <TooltipBox
        title={`${d.label}:00–${d.label}:59 ${zone}`}
        rows={series.map((s) => ({ label: s.label, value: d[s.key], color: s.color }))}
      />
    ) : null;
  };
  const busiest = hourly.reduce((b, h) => (h.total > b.total ? h : b), hourly[0]!);
  return (
    <ChartCard
      title={title}
      fill={HEIGHT}
      description={`Hour of day, ${zone}.`}
      {...(series.length > 1 ? { headerExtra: <Legend items={[...series].reverse()} /> } : {})}
      summary={`${title}: busiest hour ${String(busiest.hour).padStart(2, '0')}:00 ${zone} with ${busiest.total} events.`}
      empty={total === 0}
      emptyText="No timestamped events for the current filters."
      rows={data}
      columns={[
        { header: 'Hour', cell: (r) => `${r.label}:00` },
        ...series.map((s) => ({
          header: s.label,
          cell: (r: (typeof data)[number]) => r[s.key],
          numeric: true,
        })),
        ...(onSelectHour
          ? [
              filterColumn<(typeof data)[number]>(
                'Apply',
                (r) => onSelectHour(r.hour),
                (r) => selected.includes(r.hour),
              ),
            ]
          : []),
      ]}
      {...(onSelectHour ? { hint: 'Select an hour to filter by hour of day.' } : {})}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 8, right: 4, bottom: 0, left: -8 }}
          onClick={(state: unknown) => {
            const i = activeIndex(state);
            if (i !== null && onSelectHour) onSelectHour(i);
          }}
          barCategoryGap={2}
        >
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis dataKey="label" interval={2} {...axisProps} />
          <YAxis allowDecimals={false} width={52} {...axisProps} />
          <Tooltip content={tooltip} cursor={CURSOR_FILL} isAnimationActive={false} />
          {series.map((s) => (
            <Bar
              key={s.key}
              dataKey={s.key}
              name={s.label}
              stackId="h"
              fill={s.color}
              stroke={CHART.surface}
              strokeWidth={1}
              isAnimationActive={false}
              cursor={onSelectHour ? 'pointer' : undefined}
            >
              {data.map((d) => (
                <Cell key={d.hour} fillOpacity={dimmed(selected, d.hour)} />
              ))}
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

// ---------------------------------------------------------------- alert timeline

export function AlertTimelineChart({
  points,
  bucketMs,
  timeZone,
  onSelectBucket,
}: {
  points: AlertPoint[];
  bucketMs: number;
  timeZone: DisplayTimeZone;
  onSelectBucket?: (start: number, end: number) => void;
}) {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const present = order.filter((k) => points.some((p) => p[k] > 0));
  const total = points.reduce((s, p) => s + order.reduce((x, k) => x + p[k], 0), 0);
  const span = points.length > 0 ? points[points.length - 1]!.t - points[0]!.t : 0;
  const tooltip = (props: RechartsTooltipProps<AlertPoint>) => {
    const p = payloadOf(props);
    return p ? (
      <TooltipBox
        title={`Detections starting ${formatTimestamp(p.t, timeZone)}`}
        rows={[...order]
          .reverse()
          .filter((k) => p[k] > 0)
          .map((k) => ({ label: k, value: p[k], color: SEVERITY_COLORS[k] }))}
      />
    ) : null;
  };
  return (
    <ChartCard
      title="Detection timeline"
      description="Detections by start time and severity."
      headerExtra={
        <Legend
          items={[...present].reverse().map((k) => ({ label: k, color: SEVERITY_COLORS[k] }))}
        />
      }
      summary={`Detection timeline: ${total} detections with a known start time across ${points.length} buckets.`}
      empty={total === 0}
      emptyText="No timed detections for the current filters."
      rows={points.filter((p) => order.some((k) => p[k] > 0))}
      columns={[
        { header: 'Bucket start', cell: (p) => formatTimestamp(p.t, timeZone) },
        ...[...order].reverse().map((k) => ({
          header: k,
          cell: (p: AlertPoint) => p[k],
          numeric: true,
        })),
        ...(onSelectBucket
          ? [
              filterColumn<AlertPoint>('Filter to period', (p) =>
                onSelectBucket(p.t, p.t + bucketMs - 1),
              ),
            ]
          : []),
      ]}
      {...(onSelectBucket ? { hint: 'Select a period to filter to it.' } : {})}
    >
      <ResponsiveContainer width="100%" height={150}>
        <BarChart
          data={points}
          margin={{ top: 8, right: 4, bottom: 0, left: -8 }}
          barCategoryGap={1}
          onClick={(state: unknown) => {
            const i = activeIndex(state);
            const p = i === null ? undefined : points[i];
            if (p && onSelectBucket) onSelectBucket(p.t, p.t + bucketMs - 1);
          }}
        >
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={(t: number) => formatAxisTime(t, timeZone, span)}
            minTickGap={48}
            {...axisProps}
          />
          <YAxis allowDecimals={false} width={52} {...axisProps} />
          <Tooltip content={tooltip} cursor={CURSOR_FILL} isAnimationActive={false} />
          {order.map((k) => (
            <Bar
              key={k}
              dataKey={k}
              name={k}
              stackId="s"
              fill={SEVERITY_COLORS[k]}
              stroke={CHART.surface}
              strokeWidth={1}
              isAnimationActive={false}
              cursor={onSelectBucket ? 'pointer' : undefined}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
