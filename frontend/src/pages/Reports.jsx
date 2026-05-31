import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, ArrowLeft, Download, FileText } from 'lucide-react';
import { scanApi, reportApi, saveBlob } from '../api/scans.js';
import { Button } from '../components/ui.jsx';
import { Badge } from '../components/ui/Badge.jsx';
import { SkeletonCard } from '../components/ui/Skeleton.jsx';

const DOWNLOADS = [
  { fmt: 'pdf', label: 'PDF', ext: 'pdf' },
  { fmt: 'html', label: 'HTML', ext: 'html' },
  { fmt: 'csv', label: 'CSV', ext: 'csv' },
  { fmt: 'markdown', label: 'MD', ext: 'md' },
  { fmt: 'json', label: 'JSON', ext: 'json' },
];

export default function Reports() {
  const navigate = useNavigate();
  const [downloading, setDownloading] = useState(null); // `${scanId}:${fmt}`

  const { data, isLoading } = useQuery({
    queryKey: ['scans', 'completed'],
    queryFn: () => scanApi.list(1, 50),
  });

  const completedScans = (data?.scans || []).filter((s) => s.status === 'completed');

  // Quick stats across reports.
  const totals = completedScans.reduce(
    (acc, s) => {
      acc.vulns += s.stats?.totalVulnerabilities || 0;
      if ((s.stats?.securityScore ?? 100) < (acc.worstScore ?? 101)) {
        acc.worstScore = s.stats?.securityScore ?? 100;
        acc.worstTarget = s.targetDomain;
      }
      return acc;
    },
    { vulns: 0, worstScore: null, worstTarget: null },
  );

  async function download(scanId, fmt, ext, domain, scanNumber) {
    const key = `${scanId}:${fmt}`;
    setDownloading(key);
    try {
      const blob = await reportApi.download(scanId, fmt);
      saveBlob(blob, `SmartFuzz_Report_${domain}_Scan${scanNumber}.${ext}`);
    } catch { /* reset below */ }
    setDownloading(null);
  }

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center gap-3">
          <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg" aria-label="Back">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">
        <div>
          <h1 className="font-mono text-xl font-bold text-fg">Reports</h1>
          <p className="font-mono text-sm text-fg-muted">Download reports for completed scans</p>
        </div>

        {/* Quick stats */}
        {completedScans.length > 0 && (
          <div className="grid grid-cols-3 gap-3">
            <div className="card p-4">
              <div className="font-mono text-xs text-fg-muted">Reports</div>
              <div className="font-mono text-2xl font-bold text-fg">{completedScans.length}</div>
            </div>
            <div className="card p-4">
              <div className="font-mono text-xs text-fg-muted">Total Vulns</div>
              <div className="font-mono text-2xl font-bold text-fg">{totals.vulns}</div>
            </div>
            <div className="card p-4">
              <div className="font-mono text-xs text-fg-muted">Most Vulnerable</div>
              <div className="truncate font-mono text-sm font-bold text-severity-high">{totals.worstTarget || '—'}</div>
            </div>
          </div>
        )}

        {isLoading ? (
          <div className="space-y-3"><SkeletonCard /><SkeletonCard /></div>
        ) : completedScans.length === 0 ? (
          <div className="card p-8 text-center">
            <FileText className="mx-auto mb-3 h-10 w-10 text-fg-subtle" />
            <p className="font-mono text-sm text-fg-muted">No completed scans yet.</p>
            <Button className="mt-4" onClick={() => navigate('/scan/new')}>Start a Scan</Button>
          </div>
        ) : (
          <div className="card divide-y divide-border">
            {completedScans.map((s) => {
              const score = s.stats?.securityScore ?? 100;
              return (
                <div key={s.id} className="px-4 py-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-sm font-bold text-fg">{s.targetUrl}</p>
                      <p className="mt-0.5 font-mono text-xs text-fg-muted">
                        Scan #{s.scanNumber} · {new Date(s.createdAt).toLocaleDateString()}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <Badge severity={score >= 80 ? 'low' : score >= 50 ? 'medium' : 'critical'} label={`${score}/100`} showIcon={false} />
                        {['critical', 'high', 'medium'].map((sev) => (s.stats?.[sev] > 0 ? (
                          <Badge key={sev} severity={sev} label={`${s.stats[sev]} ${sev}`} showIcon={false} />
                        ) : null))}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 sm:shrink-0">
                      <Button variant="ghost" onClick={() => navigate(`/results/${s.id}`)}>View</Button>
                      {DOWNLOADS.map((d) => (
                        <Button
                          key={d.fmt}
                          variant="ghost"
                          loading={downloading === `${s.id}:${d.fmt}`}
                          onClick={() => download(s.id, d.fmt, d.ext, s.targetDomain, s.scanNumber)}
                        >
                          <Download className="h-3 w-3" /> {d.label}
                        </Button>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
