import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Shield, ArrowLeft, CheckCircle2, ShieldCheck, Loader2 } from 'lucide-react';
import { scanApi, vulnApi } from '../api/scans.js';
import { Button, Alert } from '../components/ui.jsx';
import { Badge } from '../components/ui/Badge.jsx';
import { CVSSMeter } from '../components/CVSSMeter.jsx';
import { FixGuidePanel } from '../components/FixGuidePanel.jsx';
import { SkeletonCard } from '../components/ui/Skeleton.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

// FixGuide — a full-screen reading experience for a single finding. Loads the
// vulnerability (enriched server-side with its fix guide), renders a compact
// CVSS breakdown, the 3-tab guide, and the verify/mark-fixed actions.

export default function FixGuide() {
  const { scanId, vulnId } = useParams();
  const navigate = useNavigate();
  const [verifyResult, setVerifyResult] = useState(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scan', scanId, 'vuln', vulnId],
    queryFn: () => scanApi.vulnerability(scanId, vulnId),
    enabled: !!scanId && !!vulnId,
  });

  const vuln = data?.vulnerability;

  const verify = useMutation({
    mutationFn: () => vulnApi.verify(vulnId),
    onSuccess: () => {
      setVerifyResult('queued');
      // Re-poll a couple of times so the persisted status shows up.
      setTimeout(() => refetch(), 2000);
      setTimeout(() => refetch(), 5000);
    },
  });

  const markFixed = useMutation({
    mutationFn: (fixed) => vulnApi.markFixed(vulnId, fixed),
    onSuccess: () => refetch(),
  });

  if (isLoading) {
    return <div className="mx-auto max-w-3xl space-y-3 p-6"><SkeletonCard /><SkeletonCard /></div>;
  }
  if (!vuln) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Alert variant="error">Vulnerability not found.</Alert>
        <Button className="mt-4" variant="ghost" onClick={() => navigate(`/results/${scanId}`)}>← Back to Results</Button>
      </div>
    );
  }

  const verified = vuln.verificationStatus === 'verified_fixed';
  const persists = vuln.verificationStatus === 'verified_persists';

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-center gap-3">
          <button onClick={() => navigate(`/results/${scanId}`)} className="text-fg-muted hover:text-fg" aria-label="Back">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-3xl space-y-5 px-4 py-6">
        {/* Title */}
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge severity={vuln.severity} score={vuln.cvssScore} />
            {verified && (
              <span className="inline-flex items-center gap-1 font-mono text-xs text-accent"><CheckCircle2 size={14} /> Verified Fixed</span>
            )}
          </div>
          <h1 className="font-mono text-2xl font-bold text-fg">{getVulnLabel(vuln.type)}</h1>
          <p className="mt-1 break-all font-mono text-sm text-fg-muted">{vuln.url}{vuln.param ? ` · ${vuln.param}` : ''}</p>
        </div>

        {/* CVSS */}
        <div className="card p-4">
          <CVSSMeter vector={vuln.cvssVector} score={vuln.cvssScore} compact />
        </div>

        {/* Verify result banner */}
        {verified && <Alert variant="success">✅ Verified Fixed — the original payload no longer triggers this vulnerability.</Alert>}
        {persists && <Alert variant="error">❌ Still Vulnerable — the response still matches the original finding.</Alert>}
        {verifyResult === 'queued' && !verified && !persists && (
          <Alert variant="info">Verification queued — re-testing the endpoint with the original payload…</Alert>
        )}

        {/* 3-layer fix guide */}
        <div className="card p-4">
          <FixGuidePanel fixGuide={vuln.fixGuide} cwe={vuln.cwe} />
        </div>

        {/* Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
          <Button variant="ghost" onClick={() => navigate(`/results/${scanId}`)}>← Back to Results</Button>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              onClick={() => markFixed.mutate(!vuln.markedFixedByUser)}
              loading={markFixed.isPending}
            >
              <CheckCircle2 className="h-4 w-4" /> {vuln.markedFixedByUser ? 'Marked Fixed' : 'Mark as Fixed'}
            </Button>
            <Button onClick={() => verify.mutate()} loading={verify.isPending}>
              {verify.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Run Verify Fix
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}
