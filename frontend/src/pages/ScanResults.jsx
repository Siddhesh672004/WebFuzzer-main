import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, Download, ChevronDown, ChevronRight, ArrowLeft } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button, Alert } from '../components/ui.jsx';

const SEV_COLOR = { critical: '#F85149', high: '#F78166', medium: '#D29922', low: '#58A6FF', informational: '#8B949E' };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(null);
  const [filter, setFilter] = useState('all');

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
  const filtered = filter === 'all' ? vulns : vulns.filter((v) => v.severity === filter);

  if (scanLoading || vulnLoading) {
    return <div className="flex h-screen items-center justify-center font-mono text-fg-muted"><span className="terminal-cursor">loading</span></div>;
  }

  const score = scan?.stats?.securityScore ?? 100;
  const scoreColor = score >= 80 ? '#3FB950' : score >= 50 ? '#D29922' : '#F85149';

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg">
              <ArrowLeft className="h-5 w-5" />
            </button>
            <Shield className="h-6 w-6 text-accent" />
            <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
          </div>
          <div className="flex gap-2">
            {scan?.targetDomain && (
              <Button variant="ghost" onClick={() => navigate(`/compare/${scan.targetDomain}`)}>
                Compare Scans
              </Button>
            )}
            <Button variant="ghost">
              <Download className="h-4 w-4" />
              Report
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="font-mono text-xl font-bold text-fg">{scan?.targetUrl}</h1>
            <p className="font-mono text-sm text-fg-muted">Scan #{scan?.scanNumber} · {scan?.status}</p>
          </div>
          <div className="text-right">
            <div className="font-mono text-4xl font-bold" style={{ color: scoreColor }}>{score}</div>
            <div className="font-mono text-xs text-fg-muted">/ 100</div>
          </div>
        </div>

        {/* Severity summary */}
        <div className="grid grid-cols-5 gap-2">
          {SEV_ORDER.map((sev) => {
            const count = vulns.filter((v) => v.severity === sev).length;
            return (
              <button
                key={sev}
                onClick={() => setFilter(filter === sev ? 'all' : sev)}
                className={`card p-3 text-center transition-colors ${filter === sev ? 'border-2' : ''}`}
                style={filter === sev ? { borderColor: SEV_COLOR[sev] } : {}}
              >
                <div className="font-mono text-2xl font-bold" style={{ color: SEV_COLOR[sev] }}>{count}</div>
                <div className="font-mono text-xs text-fg-muted capitalize">{sev}</div>
              </button>
            );
          })}
        </div>

        {/* Vulnerability list */}
        <div className="card">
          <div className="border-b border-border px-4 py-3 flex items-center justify-between">
            <h2 className="font-mono text-sm font-bold text-fg">
              Vulnerabilities {filter !== 'all' && `(${filter})`} — {filtered.length}
            </h2>
            {filter !== 'all' && (
              <button onClick={() => setFilter('all')} className="font-mono text-xs text-accent hover:underline">
                clear filter
              </button>
            )}
          </div>
          {filtered.length === 0 ? (
            <div className="p-8 text-center font-mono text-sm text-fg-subtle">No vulnerabilities found.</div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map((v) => (
                <div key={v.id || v._id}>
                  <button
                    className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-subtle text-left"
                    onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                  >
                    <span className="w-20 shrink-0 font-mono text-xs font-bold" style={{ color: SEV_COLOR[v.severity] }}>
                      {v.severity?.toUpperCase()}
                    </span>
                    <span className="font-mono text-sm text-fg flex-1">{v.type}</span>
                    <span className="font-mono text-xs text-fg-muted truncate max-w-xs">{v.url}</span>
                    <span className="font-mono text-xs text-fg-subtle">{v.cvssScore?.toFixed(1)}</span>
                    {expanded === v.id ? <ChevronDown className="h-4 w-4 text-fg-subtle shrink-0" /> : <ChevronRight className="h-4 w-4 text-fg-subtle shrink-0" />}
                  </button>
                  {expanded === v.id && (
                    <div className="px-4 pb-4 space-y-3 bg-bg-inset">
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div>
                          <p className="font-mono text-xs text-fg-muted mb-1">Parameter</p>
                          <code className="font-mono text-sm text-fg">{v.param || '—'}</code>
                        </div>
                        <div>
                          <p className="font-mono text-xs text-fg-muted mb-1">CVSS Vector</p>
                          <code className="font-mono text-xs text-fg-subtle break-all">{v.cvssVector || '—'}</code>
                        </div>
                      </div>
                      {v.payload && (
                        <div>
                          <p className="font-mono text-xs text-fg-muted mb-1">Payload</p>
                          <code className="block font-mono text-xs text-severity-medium bg-bg p-2 rounded border border-border overflow-x-auto">{v.payload}</code>
                        </div>
                      )}
                      {v.evidence && (
                        <div>
                          <p className="font-mono text-xs text-fg-muted mb-1">Evidence</p>
                          <p className="font-mono text-xs text-fg">{v.evidence}</p>
                        </div>
                      )}
                      {v.owaspRef && (
                        <a href={v.owaspRef} target="_blank" rel="noreferrer" className="font-mono text-xs text-accent hover:underline">
                          OWASP Reference →
                        </a>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
