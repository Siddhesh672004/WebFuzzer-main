import { CheckCircle2, ShieldCheck, Loader2 } from 'lucide-react';
import { ProgressBar } from './ui/ProgressBar.jsx';
import { Badge } from './ui/Badge.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

// RemediationTracker — fix-progress overview plus per-finding quick actions.
// "Fixed" counts a finding as resolved when the engine verified it fixed OR the
// user marked it fixed. Progress bar animates as the count changes.

function isResolved(v) {
  return v.verificationStatus === 'verified_fixed' || v.markedFixedByUser;
}

export function RemediationTracker({ vulnerabilities = [], onVerify, onMarkFixed, verifyingId }) {
  const total = vulnerabilities.length;
  const fixed = vulnerabilities.filter(isResolved).length;
  const pct = total ? Math.round((fixed / total) * 100) : 0;

  return (
    <div className="card p-4">
      <div className="mb-3">
        <div className="flex items-baseline justify-between">
          <h3 className="font-mono text-sm font-semibold text-fg">Remediation Progress</h3>
          <span className="font-mono text-xs text-fg-muted">{fixed} of {total} fixed ({pct}%)</span>
        </div>
        <ProgressBar value={pct} scoreColor className="mt-2" height="h-2" />
      </div>

      <div className="max-h-72 space-y-1.5 overflow-y-auto">
        {vulnerabilities.map((v) => {
          const resolved = isResolved(v);
          const verifying = verifyingId === v.id;
          return (
            <div key={v.id} className="flex items-center gap-2 rounded-md border border-border-muted px-2.5 py-1.5">
              <Badge severity={v.severity} showIcon={false} />
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{getVulnLabel(v.type)}</span>
              {resolved ? (
                <span className="inline-flex items-center gap-1 font-mono text-[11px] text-accent">
                  <CheckCircle2 size={13} /> {v.verificationStatus === 'verified_fixed' ? 'Verified' : 'Fixed'}
                </span>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => onMarkFixed?.(v, true)}
                    className="rounded border border-border px-2 py-0.5 font-mono text-[10px] text-fg-muted hover:text-fg"
                  >
                    Mark
                  </button>
                  <button
                    onClick={() => onVerify?.(v)}
                    disabled={verifying}
                    className="inline-flex items-center gap-1 rounded bg-accent-dim px-2 py-0.5 font-mono text-[10px] text-white hover:bg-accent-glow disabled:opacity-50"
                  >
                    {verifying ? <Loader2 size={11} className="animate-spin" /> : <ShieldCheck size={11} />} Verify
                  </button>
                </div>
              )}
            </div>
          );
        })}
        {total === 0 && <p className="py-4 text-center font-mono text-xs text-fg-subtle">No findings to track.</p>}
      </div>
    </div>
  );
}

export default RemediationTracker;
