import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, ArrowLeft, Download, FileText } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button } from '../components/ui.jsx';

const SEV_COLOR = { critical: '#F85149', high: '#F78166', medium: '#D29922', low: '#58A6FF', informational: '#8B949E' };

function downloadBlob(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
}

async function downloadReport(scanId, format, domain, scanNumber) {
  const res = await fetch(`/api/reports/${scanId}/${format}`, { credentials: 'include' });
  if (!res.ok) return;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  downloadBlob(url, `SmartFuzz_Report_${domain}_Scan${scanNumber}.${format}`);
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ['scans', 'completed'],
    queryFn: () => scanApi.list(1, 50),
  });

  const completedScans = (data?.scans || []).filter((s) => s.status === 'completed');

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
          <h1 className="font-mono text-xl font-bold text-fg">Reports</h1>
          <p className="font-mono text-sm text-fg-muted">Download reports for completed scans</p>
        </div>

        {isLoading ? (
          <div className="card p-8 text-center font-mono text-sm text-fg-muted">
            <span className="terminal-cursor">loading</span>
          </div>
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
              const scoreColor = score >= 80 ? '#3FB950' : score >= 50 ? '#D29922' : '#F85149';
              return (
                <div key={s.id} className="px-4 py-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-sm font-bold text-fg truncate">{s.targetUrl}</p>
                      <p className="font-mono text-xs text-fg-muted mt-0.5">
                        Scan #{s.scanNumber} · {new Date(s.createdAt).toLocaleDateString()}
                      </p>
                      <div className="mt-2 flex items-center gap-3">
                        <span className="font-mono text-sm font-bold" style={{ color: scoreColor }}>{score}/100</span>
                        {['critical', 'high', 'medium'].map((sev) => s.stats?.[sev] > 0 && (
                          <span key={sev} className="font-mono text-xs" style={{ color: SEV_COLOR[sev] }}>
                            {s.stats[sev]} {sev}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 shrink-0">
                      <Button variant="ghost" onClick={() => navigate(`/results/${s.id}`)}>
                        View
                      </Button>
                      {['html', 'pdf', 'csv', 'markdown'].map((fmt) => (
                        <Button
                          key={fmt}
                          variant="ghost"
                          onClick={() => downloadReport(s.id, fmt, s.targetDomain, s.scanNumber)}
                        >
                          <Download className="h-3 w-3" />
                          {fmt.toUpperCase()}
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
