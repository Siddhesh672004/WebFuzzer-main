import { Shield, AlertTriangle, AlertCircle, Info, CheckCircle2, Sparkles, RotateCcw } from 'lucide-react';

// Badge — severity / status pill with consistent color coding. Colors come from
// the Tailwind `severity` tokens (which mirror shared/severity bands) so the UI
// never drifts from the data. Optionally renders an inline CVSS score.

const SEVERITY_STYLES = {
  critical: { cls: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30', Icon: AlertCircle, label: 'Critical' },
  high: { cls: 'bg-severity-high/15 text-severity-high border-severity-high/30', Icon: AlertTriangle, label: 'High' },
  medium: { cls: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30', Icon: AlertTriangle, label: 'Medium' },
  low: { cls: 'bg-severity-low/15 text-severity-low border-severity-low/30', Icon: Info, label: 'Low' },
  informational: { cls: 'bg-severity-info/15 text-severity-info border-severity-info/30', Icon: Info, label: 'Info' },
  info: { cls: 'bg-severity-info/15 text-severity-info border-severity-info/30', Icon: Info, label: 'Info' },
};

// Comparison / remediation statuses.
const STATUS_STYLES = {
  fixed: { cls: 'bg-accent/15 text-accent border-accent/30', Icon: CheckCircle2, label: 'Fixed' },
  verified_fixed: { cls: 'bg-accent/15 text-accent border-accent/30', Icon: CheckCircle2, label: 'Verified Fixed' },
  new: { cls: 'bg-severity-low/15 text-severity-low border-severity-low/30', Icon: Sparkles, label: 'New' },
  persists: { cls: 'bg-severity-high/15 text-severity-high border-severity-high/30', Icon: AlertTriangle, label: 'Persists' },
  regressed: { cls: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30', Icon: RotateCcw, label: 'Regressed' },
  pending: { cls: 'bg-fg-muted/10 text-fg-muted border-border', Icon: Shield, label: 'Pending' },
};

export function Badge({ severity, status, score, label, className = '', showIcon = true }) {
  const key = (severity || status || 'info').toLowerCase();
  const style = SEVERITY_STYLES[key] || STATUS_STYLES[key] || SEVERITY_STYLES.info;
  const { Icon } = style;
  const text = label || style.label || key;

  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-xs font-medium ${style.cls} ${className}`}
    >
      {showIcon && Icon && <Icon size={12} aria-hidden="true" />}
      <span>{text}</span>
      {typeof score === 'number' && <span className="ml-0.5 opacity-80">{score.toFixed(1)}</span>}
    </span>
  );
}

export default Badge;
