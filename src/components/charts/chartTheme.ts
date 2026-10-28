import type { Severity } from '../../types/detection';

/**
 * Chart colours for the "Graphite and Iris" style on the #18191d panel.
 * The main volume series carries the iris accent; colour beyond that is spent
 * on what needs attention: failures, errors and the entities that detections
 * are about. Other activity is drawn in neutral greys, so a red or amber mark
 * always means something. Every series also carries a text label (legend,
 * tooltip, table view), never colour alone.
 */
export const CHART = {
  surface: '#18191d',
  grid: '#25272b',
  axis: '#3b3d41',
  muted: '#9598a0',
  text: '#babec4',
  /** Ordinary volume over time: the one series that carries the accent. */
  primary: '#9d9eff',
  /** Neutral marks for ordinary activity. */
  neutral: '#7b7e86',
  neutralStrong: '#b4b7bf',
  neutralSoft: '#4b4e55',
  /** Authentication outcome: success is ordinary, failure is the signal. */
  success: '#7b7e86',
  failure: '#f2536d',
  /** HTTP status classes in stack order 2xx, 3xx, 4xx, 5xx. */
  status: {
    '1xx': '#7b7e86',
    '2xx': '#7b7e86',
    '3xx': '#4b4e55',
    '4xx': '#e2a640',
    '5xx': '#f2536d',
  } as Record<string, string>,
  /** Entities that are the subject of a detection. */
  risk: '#f2536d',
} as const;

/** Severity uses the status palette; always paired with its glyph and text label. */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f2536d',
  high: '#f5843c',
  medium: '#f0d264',
  low: '#5c9ff2',
  info: '#7b7e86',
};

export const axisProps = {
  stroke: CHART.axis,
  tick: { fill: CHART.muted, fontSize: 11 },
  tickLine: false,
  axisLine: false,
} as const;
