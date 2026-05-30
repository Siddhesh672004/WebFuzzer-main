import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, Activity, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button, Alert } from '../components/ui.jsx';

const SEVERITY_COLOR = { critical: '#F85149', high: '#F78166', medium: '#D29922', low: '#58A6FF', informational: '#8B949E' };

export default function ScanMonitor() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [moduleStatus, setModuleStatus] = useState({});
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [done, setDone] = useState(false);
  const [sseError, setSseError] = useState(null);
  const terminalRef = useRef(null);

  const { data: scanData } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id),
    refetchInterval: done ? false : 3000,
  });
  const scan = scanData?.scan;

  useEffect(() => {
    if (!id) return;
    const es = new EventSource(`/api/scans/${id}/progress`, { withCredentials: true });

    es.addEventListener('progress', (e) => {
      const d = JSON.parse(e.data);
      setProgress(d.data?.percentComplete || 0);
      setEvents((prev) => [...prev.slice(-200), { kind: 'progress', ...d.data, at: Date.now() }]);
    });
    es.addEventListener('finding', (e) => {
      const d = JSON.parse(e.data);
      setFindings((prev) => [d.data, ...prev]);
      setEvents((prev) => [...prev.slice(-200), { kind: 'finding', ...d.data, at: Date.now() }]);
    });
    es.addEventListener('module', (e) => {
      const d = JSON.parse(e.data);
      setModuleStatus((prev) => ({ ...prev, [d.data?.module]: d.data?.status }));
    });
    es.addEventListener('done', () => { setDone(true); es.close(); });
    es.onerror = () => { setSseError('Connection lost. Refreshing…'); es.close(); };

    return () => es.close();
  }, [id]);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [events]);

  const isTerminal = done || ['completed', 'failed', 'cancelled'].includes(scan?.status);

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-accent" />
            <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
          </div>
          {isTerminal && (
            <Button onClick={() => navigate(`/results/${id}`)}>View Results</Button>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 space-y-4">
        <div>
          <h1 className="font-mono text-xl font-bold text-fg">
            {scan?.targetUrl || 'Scanning…'}
          </h1>
          <p className="font-mono text-sm text-fg-muted">Scan #{scan?.scanNumber}</p>
        </div>

        {sseError && <Alert variant="warn">{sseError}</Alert>}

        {/* Progress bar */}
        <div className="card p-4">
          <div className="mb-2 flex items-center justify-between font-mono text-sm">
            <span className="text-fg-muted">Progress</span>
            <span className="text-accent">{progress}%</span>
          </div>
          <div className="h-2 w-full rounded-full bg-bg-inset">
            <div
              className="h-2 rounded-full bg-accent transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Module status */}
        <div className="card p-4">
          <h2 className="mb-3 font-mono text-sm font-bold text-fg-muted uppercase tracking-wide">Modules</h2>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-6">
            {['crawler', 'passive', 'exposed', 'tech', 'fuzzer', 'auth'].map((m) => {
              const s = moduleStatus[m] || 'pending';
              return (
                <div key={m} className="flex flex-col items-center gap-1 rounded border border-border p-2">
                  {s === 'completed' ? <CheckCircle className="h-4 w-4 text-accent" /> :
                   s === 'running' ? <Activity className="h-4 w-4 text-severity-medium animate-pulse" /> :
                   s === 'failed' ? <XCircle className="h-4 w-4 text-severity-critical" /> :
                   <Clock className="h-4 w-4 text-fg-subtle" />}
                  <span className="font-mono text-xs text-fg-muted">{m}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          {/* Live findings */}
          <div className="card p-4">
            <h2 className="mb-3 font-mono text-sm font-bold text-fg-muted uppercase tracking-wide">
              Findings ({findings.length})
            </h2>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {findings.length === 0 ? (
                <p className="font-mono text-xs text-fg-subtle">No findings yet…</p>
              ) : findings.map((f, i) => (
                <div key={i} className="flex items-center gap-2 font-mono text-xs">
                  <span className="w-16 shrink-0 font-bold" style={{ color: SEVERITY_COLOR[f.severity] }}>
                    {f.severity?.toUpperCase()}
                  </span>
                  <span className="text-fg truncate">{f.type}</span>
                  <span className="text-fg-subtle truncate">{f.url}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Terminal log */}
          <div className="card p-4">
            <h2 className="mb-3 font-mono text-sm font-bold text-fg-muted uppercase tracking-wide">Log</h2>
            <div ref={terminalRef} className="h-64 overflow-y-auto font-mono text-xs text-fg-muted space-y-0.5">
              {events.map((e, i) => (
                <div key={i} className="leading-5">
                  <span className="text-accent">{'>'}</span>{' '}
                  {e.kind === 'finding' ? (
                    <span style={{ color: SEVERITY_COLOR[e.severity] }}>
                      [{e.severity}] {e.type} @ {e.url}
                    </span>
                  ) : e.kind === 'progress' ? (
                    <span>{e.percentComplete}% — {e.currentModule} ({e.vulnerabilitiesFound} vulns)</span>
                  ) : (
                    <span>{JSON.stringify(e)}</span>
                  )}
                </div>
              ))}
              {events.length === 0 && <span className="terminal-cursor">waiting for events</span>}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
