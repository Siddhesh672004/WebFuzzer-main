import { useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, Download, ArrowLeft, Search, RefreshCw, Key } from 'lucide-react';
import { scanApi, reportApi, vulnApi, saveBlob } from '../api/scans.js';
import { Button, Alert, Input } from '../components/ui.jsx';
import { SecurityScoreGauge } from '../components/SecurityScoreGauge.jsx';
import { Badge } from '../components/ui/Badge.jsx';
import { SkeletonCard } from '../components/ui/Skeleton.jsx';
import { VulnerabilityCard } from '../components/VulnerabilityCard.jsx';
import { VulnDetailSheet } from '../components/VulnDetailSheet.jsx';
import { RemediationTracker } from '../components/RemediationTracker.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const DOWNLOADS = [
  { fmt: 'pdf', label: 'PDF', ext: 'pdf' },
  { fmt: 'html', label: 'HTML', ext: 'html' },
  { fmt: 'csv', label: 'CSV', ext: 'csv' },
  { fmt: 'markdown', label: 'Markdown', ext: 'md' },
  { fmt: 'json', label: 'JSON', ext: 'json' },
];

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [filter, setFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState(null); // currently open vuln (with fixGuide)
  const [downloading, setDownloading] = useState(null);
  const [verifyingId, setVerifyingId] = useState(null);

  const { data: scanData, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id),
  });
  const { data: vulnData, isLoading: vulnLoading } = useQuery({
    queryKey: ['scan', id, 'vulns'],
    queryFn: () => scanApi.vulnerabilities(id),
    enabled: !!id,
  });

  const scan = scanData?.scan;
  const vulns = vulnData?.vulnerabilities || [];

  const types = useMemo(() => [...new Set(vulns.map((v) => v.type))], [vulns]);
  const hasSecrets = useMemo(() => vulns.some((v) => v.type === 'exposed_secret'), [vulns]);

  const filtered = useMemo(() => {
    return vulns.filter((v) => {
      if (filter !== 'all' && v.severity !== filter) return false;
      if (typeFilter !== 'all' && v.type !== typeFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!`${v.url} ${v.param}`.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [vulns, filter, typeFilter, search]);

  const markFixed = useMutation({
    mutationFn: ({ vulnId, fixed }) => vulnApi.markFixed(vulnId, fixed),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['scan', id, 'vulns'] });
      if (open && res?.vulnerability) setOpen({ ...open, ...res.vulnerability });
    },
  });

  const verify = useMutation({
    mutationFn: (vulnId) => vulnApi.verify(vulnId),
    onMutate: (vulnId) => setVerifyingId(vulnId),
    onSettled: () => setTimeout(() => {
      setVerifyingId(null);
      qc.invalidateQueries({ queryKey: ['scan', id, 'vulns'] });
    }, 1500),
  });

  async function openVuln(vuln) {
    setOpen(vuln); // show immediately
    try {
      const res = await scanApi.vulnerability(id, vuln.id);
      if (res?.vulnerability) setOpen(res.vulnerability); // enriched with fixGuide
    } catch { /* keep the summary we have */ }
  }

  async function download(fmt, ext) {
    setDownloading(fmt);
    try {
      const blob = await reportApi.download(id, fmt);
      saveBlob(blob, `SmartFuzz_${scan?.targetDomain || 'scan'}_Scan${scan?.scanNumber || ''}.${ext}`);
    } catch { /* surfaced via button state reset */ }
    setDownloading(null);
  }

  if (scanLoading || vulnLoading) {
    return (
      <div className="mx-auto max-w-6xl space-y-3 p-6">
        <SkeletonCard /><SkeletonCard /><SkeletonCard />
      </div>
    );
  }

  const score = scan?.stats?.securityScore ?? 100;

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg" aria-label="Back">
              <ArrowLeft className="h-5 w-5" />
            </button>
            <Shield className="h-6 w-6 text-accent" />
            <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
          </div>
          <div className="flex flex-wrap gap-2">
            {scan?.targetDomain && (
              <Button variant="ghost" onClick={() => navigate(`/compare/${scan.targetDomain}`)}>Compare</Button>
            )}
            <Button variant="ghost" onClick={() => scanApi.create(scan.targetUrl).then((r) => navigate(`/scan/${r.scan.id}`))}>
              <RefreshCw className="h-4 w-4" /> Rescan
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-5 px-4 py-6">
        {/* Header: target + score + downloads */}
        <div className="card flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="break-all font-mono text-xl font-bold text-fg">{scan?.targetUrl}</h1>
            <p className="font-mono text-sm text-fg-muted">
              Scan #{scan?.scanNumber} · {scan?.status}
              {scan?.stats?.totalEndpoints != null && ` · ${scan.stats.totalEndpoints} endpoints`}
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {SEV_ORDER.map((sev) => {
                const count = vulns.filter((v) => v.severity === sev).length;
                if (!count) return null;
                return <Badge key={sev} severity={sev} label={`${count} ${sev}`} />;
              })}
            </div>
          </div>
          <SecurityScoreGauge score={score} />
        </div>

        {/* Download buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-fg-muted">Download report:</span>
          {DOWNLOADS.map((d) => (
            <Button key={d.fmt} variant="ghost" loading={downloading === d.fmt} onClick={() => download(d.fmt, d.ext)}>
              <Download className="h-3.5 w-3.5" /> {d.label}
            </Button>
          ))}
        </div>

        <div className="grid gap-5 lg:grid-cols-3">
          <div className="lg:col-span-2">
            {/* Filters */}
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {['all', ...SEV_ORDER].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilter(sev)}
                  className={`rounded-full border px-3 py-1 font-mono text-xs capitalize ${
                    filter === sev ? 'border-accent bg-accent/10 text-accent' : 'border-border text-fg-muted hover:text-fg'
                  }`}
                >
                  {sev}
                </button>
              ))}
              {hasSecrets && (
                <button
                  onClick={() => setTypeFilter(typeFilter === 'exposed_secret' ? 'all' : 'exposed_secret')}
                  className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 font-mono text-xs ${
                    typeFilter === 'exposed_secret'
                      ? 'border-severity-medium bg-severity-medium/10 text-severity-medium'
                      : 'border-border text-fg-muted hover:text-fg'
                  }`}
                >
                  <Key size={12} /> Secrets
                </button>
              )}
              {types.length > 0 && (
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="rounded-md border border-border bg-bg-inset px-2 py-1 font-mono text-xs text-fg"
                >
                  <option value="all">All types</option>
                  {types.map((t) => <option key={t} value={t}>{getVulnLabel(t)}</option>)}
                </select>
              )}
              <div className="relative ml-auto">
                <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-subtle" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="endpoint or param"
                  inputMode="url"
                  className="w-44 rounded-md border border-border bg-bg-inset py-1 pl-7 pr-2 font-mono text-xs text-fg placeholder:text-fg-subtle focus:outline-none focus:ring-1 focus:ring-accent/40"
                />
              </div>
            </div>

            {/* Findings */}
            {filtered.length === 0 ? (
              vulns.length === 0 ? (
                <Alert variant="success">✅ No vulnerabilities detected. This target passed all checks.</Alert>
              ) : (
                <div className="card p-6 text-center font-mono text-sm text-fg-subtle">No findings match these filters.</div>
              )
            ) : (
              <div className="space-y-2">
                {filtered.map((v, i) => (
                  <VulnerabilityCard key={v.id} vuln={v} index={i} onOpen={openVuln} />
                ))}
              </div>
            )}
          </div>

          {/* Remediation sidebar */}
          <div className="lg:col-span-1">
            <RemediationTracker
              vulnerabilities={vulns}
              verifyingId={verifyingId}
              onMarkFixed={(v, fixed) => markFixed.mutate({ vulnId: v.id, fixed })}
              onVerify={(v) => verify.mutate(v.id)}
            />
          </div>
        </div>
      </main>

      <VulnDetailSheet
        vuln={open}
        fixGuide={open?.fixGuide}
        isOpen={!!open}
        busy={verifyingId === open?.id}
        onClose={() => setOpen(null)}
        onMarkFixed={(fixed) => open && markFixed.mutate({ vulnId: open.id, fixed })}
        onVerify={() => open && verify.mutate(open.id)}
      />
    </div>
  );
}
