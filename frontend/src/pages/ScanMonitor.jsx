import { useEffect, useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, CheckCircle2 } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button, Alert } from '../components/ui.jsx';
import { ProgressBar } from '../components/ui/ProgressBar.jsx';
import { ModuleStatusPanel } from '../components/ModuleStatusPanel.jsx';
import { ScanTerminal } from '../components/ScanTerminal.jsx';
import { VulnerabilityCard } from '../components/VulnerabilityCard.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

// Live scan monitor. Subscribes to the backend SSE stream and falls back to
// polling GET /scans/:id if the stream drops. Renders module status, a live
// findings feed, and a virtualized terminal log.

function ts() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

export default function ScanMonitor() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [moduleStatus, setModuleStatus] = useState({});
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [done, setDone] = useState(false);
  const [sseError, setSseError] = useState(null);

  const { data: scanData } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id),
    refetchInterval: done ? false : 3000, // SSE-drop fallback
  });
  const scan = scanData?.scan;

  const pushLog = (message, type = 'info') =>
    setLogs((prev) => [...prev.slice(-5000), { timestamp: ts(), message, type }]);

  useEffect(() => {
    if (!id) return undefined;
    const es = new EventSource(`/api/scans/${id}/progress`, { withCredentials: true });

    es.addEventListener('progress', (e) => {
      const d = JSON.parse(e.data);
      setProgress(d.data?.percentComplete || 0);
      pushLog(`${d.data?.percentComplete ?? 0}% — ${d.data?.currentModule || ''} (${d.data?.vulnerabilitiesFound ?? 0} vulns)`);
    });
    es.addEventListener('finding', (e) => {
      const d = JSON.parse(e.data).data;
      setFindings((prev) => [{ ...d, id: `${d.type}-${d.url}-${d.param}-${prev.length}` }, ...prev]);
      pushLog(`[${d.severity}] ${getVulnLabel(d.type)} @ ${d.url}`, 'found');
    });
    es.addEventListener('module', (e) => {
      const d = JSON.parse(e.data).data;
      setModuleStatus((prev) => ({ ...prev, [d.module]: { status: d.status, summary: d.summary } }));
      pushLog(`module ${d.module}: ${d.status}`, d.status === 'failed' ? 'error' : 'info');
    });
    es.addEventListener('status', (e) => {
      const d = JSON.parse(e.data).data;
      pushLog(`scan ${d.status}`, 'info');
    });
    es.addEventListener('done', () => {
      setDone(true);
      setProgress(100);
      pushLog('scan complete', 'success');
      es.close();
    });
    es.onerror = () => { setSseError('Live stream interrupted — falling back to polling.'); es.close(); };

    return () => es.close();
  }, [id]);

  const isTerminal = done || ['completed', 'failed', 'cancelled'].includes(scan?.status);
  const counts = useMemo(() => {
    const c = {};
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [findings]);

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-accent" />
            <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
          </div>
          {isTerminal && <Button onClick={() => navigate(`/results/${id}`)}>View Full Report</Button>}
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">
        <div>
          <h1 className="break-all font-mono text-xl font-bold text-fg">{scan?.targetUrl || 'Scanning…'}</h1>
          <p className="font-mono text-sm text-fg-muted">Scan #{scan?.scanNumber}</p>
        </div>

        {sseError && <Alert variant="warn">{sseError}</Alert>}

        {isTerminal && (
          <Alert variant="success">
            <span className="inline-flex items-center gap-2">
              <CheckCircle2 size={16} /> Scan complete — {findings.length} findings.
            </span>
          </Alert>
        )}

        <div className="card p-4">
          <div className="mb-2 flex items-center justify-between font-mono text-sm">
            <span className="text-fg-muted">Progress</span>
            <span className="text-accent">{progress}%</span>
          </div>
          <ProgressBar value={progress} height="h-2.5" />
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">Modules</h2>
            <ModuleStatusPanel modules={moduleStatus} />
          </div>

          <div>
            <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">
              Findings ({findings.length})
            </h2>
            <div className="max-h-[340px] space-y-2 overflow-y-auto">
              {findings.length === 0 ? (
                <p className="font-mono text-xs text-fg-subtle">No findings yet…</p>
              ) : (
                findings.map((f, i) => (
                  <VulnerabilityCard key={f.id} vuln={f} index={i} onOpen={() => isTerminal && navigate(`/results/${id}`)} />
                ))
              )}
            </div>
          </div>
        </div>

        <div>
          <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">Live Log</h2>
          <ScanTerminal logs={logs} />
        </div>
      </main>
    </div>
  );
}
