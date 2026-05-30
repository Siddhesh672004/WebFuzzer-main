import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, ArrowLeft, TrendingUp } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button } from '../components/ui.jsx';

const STATUS_STYLE = {
  VULNERABLE: { color: '#F85149', label: '🔴 VULN' },
  FIXED: { color: '#3FB950', label: '✅ FIXED' },
  NEW: { color: '#F78166', label: '🆕 NEW' },
  REGRESSED: { color: '#D29922', label: '⚠️ REGRESSED' },
};

export default function Comparison() {
  const { domain } = useParams();
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ['scans', 'domain', domain],
    queryFn: () => scanApi.byDomain(domain),
    enabled: !!domain,
  });

  const scans = data?.scans || [];

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center font-mono text-fg-muted"><span className="terminal-cursor">loading</span></div>;
  }

  // Build comparison table from scan stats.
  const scanNumbers = scans.map((s) => s.scanNumber);

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center gap-3">
          <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 space-y-4">
        <div>
          <h1 className="font-mono text-xl font-bold text-fg">{domain}</h1>
          <p className="font-mono text-sm text-fg-muted">{scans.length} scan{scans.length !== 1 ? 's' : ''} — security progress over time</p>
        </div>

        {scans.length === 0 ? (
          <div className="card p-8 text-center font-mono text-sm text-fg-subtle">No scans found for this domain.</div>
        ) : (
          <>
            {/* Score trend */}
            <div className="card p-4">
              <h2 className="mb-3 flex items-center gap-2 font-mono text-sm font-bold text-fg-muted uppercase tracking-wide">
                <TrendingUp className="h-4 w-4" /> Security Score Trend
              </h2>
              <div className="flex items-end gap-4 overflow-x-auto pb-2">
                {scans.map((s) => {
                  const score = s.stats?.securityScore ?? 100;
                  const color = score >= 80 ? '#3FB950' : score >= 50 ? '#D29922' : '#F85149';
                  return (
                    <div key={s.id} className="flex flex-col items-center gap-1 min-w-[60px]">
                      <span className="font-mono text-lg font-bold" style={{ color }}>{score}</span>
                      <div className="w-10 rounded-t" style={{ height: `${score}px`, maxHeight: '100px', background: color, opacity: 0.7 }} />
                      <span className="font-mono text-xs text-fg-muted">#{s.scanNumber}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Scan summary table */}
            <div className="card overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Scan</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Date</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Score</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Critical</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">High</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Medium</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted">Total</th>
                    <th className="px-4 py-3 text-left font-mono text-xs text-fg-muted"></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id} className="border-b border-border hover:bg-bg-subtle">
                      <td className="px-4 py-3 font-mono text-sm text-fg">#{s.scanNumber}</td>
                      <td className="px-4 py-3 font-mono text-xs text-fg-muted">
                        {new Date(s.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3 font-mono text-sm font-bold" style={{
                        color: (s.stats?.securityScore ?? 100) >= 80 ? '#3FB950' : (s.stats?.securityScore ?? 100) >= 50 ? '#D29922' : '#F85149'
                      }}>
                        {s.stats?.securityScore ?? 100}
                      </td>
                      <td className="px-4 py-3 font-mono text-sm" style={{ color: '#F85149' }}>{s.stats?.critical || 0}</td>
                      <td className="px-4 py-3 font-mono text-sm" style={{ color: '#F78166' }}>{s.stats?.high || 0}</td>
                      <td className="px-4 py-3 font-mono text-sm" style={{ color: '#D29922' }}>{s.stats?.medium || 0}</td>
                      <td className="px-4 py-3 font-mono text-sm text-fg">{s.stats?.totalVulnerabilities || 0}</td>
                      <td className="px-4 py-3">
                        <Button variant="ghost" onClick={() => navigate(`/results/${s.id}`)}>
                          View
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
