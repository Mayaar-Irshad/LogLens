import type { Severity } from '../../types/detection';

/**
 * Chart colours for the "data terminal" style on the #131217 card surface.
 * Colour is spent on what needs attention: failures, errors and the entities
 * that detections are about. Normal activity is drawn in neutral greys, so a
 * red or amber mark always means something. Every series also carries a text
 * label (legend, tooltip, table view), never colour alone.
 */
export const CHART = {
  surface: '#131217',
  grid: '#26252b',
  axis: '#3a3a3e',
  muted: '#8a8c92',
  text: '#c4c5c9',
  /** Ordinary volume: drawn in light neutral so hue is spent on risk only. */
  primary: '#b9bbc1',
  /** Neutral marks for ordinary activity. */
  neutral: '#7d7f86',
  neutralStrong: '#b9bbc1',
  neutralSoft: '#4f5157',
  /** Authentication outcome: success is ordinary, failure is the signal. */
  success: '#7d7f86',
  failure: '#e5566f',
  /** HTTP status classes in stack order 2xx, 3xx, 4xx, 5xx. */
  status: {
    '1xx': '#7d7f86',
    '2xx': '#7d7f86',
    '3xx': '#4f5157',
    '4xx': '#d9a441',
    '5xx': '#e5566f',
  } as Record<string, string>,
  /** Entities that are the subject of a detection. */
  risk: '#e5566f',
} as const;

/** Severity uses the status palette; always paired with its text label. */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#e5566f',
  high: '#f5930b',
  medium: '#e8c547',
  low: '#4a8ad6',
  info: '#7d7f86',
};

export const axisProps = {
  stroke: CHART.axis,
  tick: { fill: CHART.muted, fontSize: 12 },
  tickLine: false,
  axisLine: false,
} as const;
