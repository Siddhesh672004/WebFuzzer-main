import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Shield, Check, Minus, X } from 'lucide-react';
import { benchmarkApi } from '../api/scans.js';
import { SecurityScoreChart } from '../components/SecurityScoreChart.jsx';
import { SkeletonCard } from '../components/ui/Skeleton.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';
import { SEVERITY_HEX } from '../lib/palette.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const SEV_COLOR = SEVERITY_HEX;

function Mark({ value }) {
  if (value === '✓') return <Check className="h-4 w-4 text-accent" aria-label="yes" />;
  if (value === '~') return <Minus className="h-4 w-4 text-severity-medium" aria-label="partial" />;
  return <X className="h-4 w-4 text-fg-subtle" aria-label="no" />;
}

export default function Benchmark() {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({ queryKey: ['benchmark'], queryFn: benchmarkApi.stats });

  const stats = data || {};
  const byType = Object.entries(stats.findingsByType || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const maxTypeCount = byType.length ? byType[0][1] : 1;
  const totalSev = SEV_ORDER.reduce((n, s) => n + (stats.findingsBySeverity?.[s] || 0), 0) || 1;
  const history = (stats.scoreTrend || []).map((s) => ({ scanNumber: s.scanNumber, score: s.score, date: s.domain }));

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-5xl items-center gap-3">
          <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg" aria-label="Back">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-5xl space-y-8 px-4 py-8 animate-slide-up">
        <div>
          <h1 className="font-display text-3xl tracking-tightest text-fg sm:text-4xl">Benchmark</h1>
          <p className="mt-1 font-mono text-sm text-fg-muted"><span className="text-accent">$</span> coverage &amp; detection metrics across your scans</p>
        </div>

        {isLoading ? (
          <div className="space-y-3"><SkeletonCard /><SkeletonCard /></div>
        ) : (
          <>
            {/* Headline stat bar */}
            <div className="grid grid-cols-2 divide-border rounded-xl border border-border bg-bg-subtle md:grid-cols-5 md:divide-x">
              {[
                { label: 'Scans run', value: stats.totalScans ?? 0 },
                { label: 'Findings', value: stats.totalFindings ?? 0 },
                { label: 'Vuln types seen', value: stats.uniqueVulnTypes ?? 0 },
                { label: 'Avg score', value: `${stats.avgSecurityScore ?? 100}` },
                { label: 'Detectable types', value: stats.detectableVulnTypes ?? 0 },
              ].map((s) => (
                <div key={s.label} className="border-t border-border px-5 py-4 first:border-t-0 md:border-t-0">
                  <div className="font-mono text-3xl text-fg">{s.value}</div>
                  <div className="mt-1 text-[13px] uppercase tracking-wide text-fg-subtle">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Score trend */}
            {history.length > 0 && <SecurityScoreChart history={history} />}

            <div className="grid gap-6 lg:grid-cols-2">
              {/* Findings by type — CSS bar list (no extra chart weight) */}
              <section>
                <h2 className="mb-3 font-display text-xl tracking-tightest text-fg">Findings by type</h2>
                {byType.length === 0 ? (
                  <div className="card p-6 text-sm text-fg-subtle">No findings recorded yet. Run a scan to populate this.</div>
                ) : (
                  <div className="card divide-y divide-border-muted">
                    {byType.map(([type, count]) => (
                      <div key={type} className="px-4 py-2.5">
                        <div className="mb-1 flex items-center justify-between">
                          <span className="text-sm text-fg">{getVulnLabel(type)}</span>
                          <span className="font-mono text-xs text-fg-muted">{count}</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-bg-inset">
                          <div className="h-full rounded-full bg-accent/70" style={{ width: `${(count / maxTypeCount) * 100}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* Severity distribution */}
              <section>
                <h2 className="mb-3 font-display text-xl tracking-tightest text-fg">Severity distribution</h2>
                <div className="card p-4">
                  <div className="flex h-3 overflow-hidden rounded-full bg-bg-inset">
                    {SEV_ORDER.map((sev) => {
                      const n = stats.findingsBySeverity?.[sev] || 0;
                      if (!n) return null;
                      return <div key={sev} style={{ width: `${(n / totalSev) * 100}%`, background: SEV_COLOR[sev] }} title={`${sev}: ${n}`} />;
                    })}
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
                    {SEV_ORDER.map((sev) => (
                      <div key={sev} className="flex items-center gap-2">
                        <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEV_COLOR[sev] }} />
                        <span className="text-[13px] capitalize text-fg-muted">{sev}</span>
                        <span className="ml-auto font-mono text-xs text-fg">{stats.findingsBySeverity?.[sev] || 0}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </div>

            {/* vs OWASP ZAP comparison */}
            <section>
              <h2 className="mb-1 font-display text-xl tracking-tightest text-fg">SmartFuzz vs OWASP ZAP</h2>
              <p className="mb-3 text-[13px] text-fg-subtle">
                Documented reference comparison (not a live measurement). ✓ reliably detected · ~ partial · ✗ not detected.
              </p>
              <div className="card overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left font-mono text-[11px] uppercase tracking-wide text-fg-subtle">
                      <th className="px-4 py-2.5 font-medium">Capability</th>
                      <th className="px-3 py-2.5 text-center font-medium text-accent">SmartFuzz</th>
                      <th className="px-3 py-2.5 text-center font-medium">ZAP</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-muted">
                    {(stats.zapComparison || []).map((row) => (
                      <tr key={row.capability}>
                        <td className="px-4 py-2.5 text-fg-muted">{row.capability}</td>
                        <td className="px-3 py-2.5"><div className="flex justify-center"><Mark value={row.smartfuzz} /></div></td>
                        <td className="px-3 py-2.5"><div className="flex justify-center"><Mark value={row.zap} /></div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}
