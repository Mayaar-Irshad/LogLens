import type { AlertStatus, Confidence, Severity } from '../../types/detection';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: '◆',
  high: '▲',
  medium: '■',
  low: '●',
  info: '○',
};

/** Severity is always shown as glyph + text, never colour alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev sev-${severity}`}>
      <span aria-hidden="true">{SEVERITY_GLYPH[severity]}</span> {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return (
    <span
      className="badge badge-outline"
      title="Strength of the evidence, not the probability of compromise"
    >
      {confidence} evidence
    </span>
  );
}

const STATUS_LABEL: Record<AlertStatus, string> = {
  open: 'Open',
  reviewed: 'Reviewed',
  unresolved: 'Unresolved',
};

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status status-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function RiskScore({ score }: { score: number }) {
  return (
    <span className="risk" title="Deterministic priority score (0–100); not a probability">
      <span className="risk-bar" aria-hidden="true">
        <span style={{ width: `${score}%` }} />
      </span>
      <span className="risk-value">{score}</span>
    </span>
  );
}
