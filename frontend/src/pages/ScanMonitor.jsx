import { useEffect, useRef, useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, CheckCircle2, Activity, Clock, Send } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { Button, Alert } from '../components/ui.jsx';
import { ProgressBar } from '../components/ui/ProgressBar.jsx';
import { ModuleStatusPanel } from '../components/ModuleStatusPanel.jsx';
import { ScanTerminal } from '../components/ScanTerminal.jsx';
import { VulnerabilityCard } from '../components/VulnerabilityCard.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

// Live scan monitor. Subscribes to the backend SSE stream and falls back to
// polling GET /scans/:id if the stream drops. Renders a prominent live activity
// terminal (the "what is it doing right now" view), per-module status, a live
// findings feed, a liveness indicator, and an elapsed timer.

function ts() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

function fmtElapsed(totalSeconds) {
  const s = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${String(m).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
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
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState({ endpointsDiscovered: 0, payloadsSent: 0, currentModule: '' });
  const [now, setNow] = useState(Date.now());
  const lastEventRef = useRef(Date.now());

  const { data: scanData } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id),
    refetchInterval: done ? false : 3000, // SSE-drop fallback
  });
  const scan = scanData?.scan;

  const pushLog = (message, type = 'info') =>
    setLogs((prev) => [...prev.slice(-5000), { timestamp: ts(), message, type }]);

  const markEvent = () => { lastEventRef.current = Date.now(); };

  useEffect(() => {
    if (!id) return undefined;
    const es = new EventSource(`/api/scans/${id}/progress`, { withCredentials: true });

    es.onopen = () => { setConnected(true); setSseError(null); markEvent(); };

    es.addEventListener('progress', (e) => {
      markEvent();
      const d = JSON.parse(e.data).data || {};
      setProgress(d.percentComplete || 0);
      setStats({
        endpointsDiscovered: d.endpointsDiscovered ?? 0,
        payloadsSent: d.payloadsSent ?? 0,
        currentModule: d.currentModule || '',
      });
    });
    es.addEventListener('activity', (e) => {
      markEvent();
      const lines = JSON.parse(e.data).data?.lines || [];
      if (lines.length === 0) return;
      setLogs((prev) => [
        ...prev.slice(-5000),
        ...lines.map((l) => ({ timestamp: ts(), message: l.message, type: l.type })),
      ]);
    });
    es.addEventListener('finding', (e) => {
      markEvent();
      const d = JSON.parse(e.data).data;
      setFindings((prev) => [{ ...d, id: `${d.type}-${d.url}-${d.param}-${prev.length}` }, ...prev]);
      pushLog(`[${d.severity}] ${getVulnLabel(d.type)} @ ${d.url}`, 'found');
    });
    es.addEventListener('module', (e) => {
      markEvent();
      const d = JSON.parse(e.data).data;
      setModuleStatus((prev) => ({ ...prev, [d.module]: { status: d.status, summary: d.summary } }));
    });
    es.addEventListener('status', (e) => {
      markEvent();
      const d = JSON.parse(e.data).data;
      pushLog(`scan ${d.status}`, 'info');
    });
    es.addEventListener('heartbeat', () => { markEvent(); });
    es.addEventListener('done', () => {
      markEvent();
      setDone(true);
      setProgress(100);
      pushLog('scan complete', 'success');
      es.close();
    });
    es.onerror = () => { setConnected(false); setSseError('Live stream interrupted — falling back to polling.'); es.close(); };

    return () => es.close();
  }, [id]);

  // 1s tick for the elapsed timer + liveness indicator.
  useEffect(() => {
    if (done) return undefined;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [done]);

  const isTerminal = done || ['completed', 'failed', 'cancelled'].includes(scan?.status);

  // Polling fallback: lift persisted progress + per-module status from the 3s
  // query into local state so the UI stays correct even if SSE drops. SSE-driven
  // terminal states win — don't regress completed/failed back to running.
  useEffect(() => {
    if (!scan) return;
    if ((scan.progress?.percentComplete ?? 0) > progress) setProgress(scan.progress.percentComplete);
    setStats((prev) => ({
      endpointsDiscovered: scan.progress?.endpointsDiscovered ?? prev.endpointsDiscovered,
      payloadsSent: scan.progress?.payloadsSent ?? prev.payloadsSent,
      currentModule: scan.progress?.currentModule || prev.currentModule,
    }));
    const ms = scan.progress?.moduleStatus;
    if (ms && typeof ms === 'object') {
      setModuleStatus((prev) => {
        const next = { ...prev };
        for (const [k, v] of Object.entries(ms)) {
          if (!next[k] || !['completed', 'failed'].includes(next[k].status)) next[k] = { status: v };
        }
        return next;
      });
    }
  }, [scan]); // eslint-disable-line react-hooks/exhaustive-deps

  const counts = useMemo(() => {
    const c = {};
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [findings]);

  // Liveness: green when the stream is open and we've seen an event recently.
  const alive = connected && now - lastEventRef.current < 20000;

  // Elapsed: from the scan's recorded start; frozen to the final duration when terminal.
  const startMs = scan?.stats?.startTime ? new Date(scan.stats.startTime).getTime()
    : scan?.createdAt ? new Date(scan.createdAt).getTime() : null;
  const elapsedSeconds = isTerminal
    ? (scan?.stats?.durationSeconds ?? 0)
    : startMs ? (now - startMs) / 1000 : 0;

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
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="break-all font-mono text-xl font-bold text-fg">{scan?.targetUrl || 'Scanning…'}</h1>
            <p className="font-mono text-sm text-fg-muted">Scan #{scan?.scanNumber}</p>
          </div>
          {/* Live status strip: liveness dot + elapsed + counters */}
          <div className="flex items-center gap-4 font-mono text-xs text-fg-muted">
            <span className="inline-flex items-center gap-1.5" title={alive ? 'Live — receiving events' : 'No recent events'}>
              <span className={`h-2.5 w-2.5 rounded-full ${isTerminal ? 'bg-fg-subtle' : alive ? 'animate-pulse bg-accent' : 'bg-severity-medium'}`} />
              {isTerminal ? 'finished' : alive ? 'live' : 'waiting…'}
            </span>
            <span className="inline-flex items-center gap-1.5"><Clock size={13} /> {fmtElapsed(elapsedSeconds)}</span>
            <span className="inline-flex items-center gap-1.5" title="Endpoints discovered"><Activity size={13} /> {stats.endpointsDiscovered}</span>
            <span className="inline-flex items-center gap-1.5" title="Payloads sent"><Send size={13} /> {stats.payloadsSent}</span>
          </div>
        </div>

        {sseError && !isTerminal && <Alert variant="warn">{sseError}</Alert>}

        {isTerminal && (
          <Alert variant="success">
            <span className="inline-flex items-center gap-2">
              <CheckCircle2 size={16} /> Scan complete — {findings.length} findings in {fmtElapsed(elapsedSeconds)}.
            </span>
          </Alert>
        )}

        <div className="card p-4">
          <div className="mb-2 flex items-center justify-between font-mono text-sm">
            <span className="text-fg-muted">{stats.currentModule ? `running: ${stats.currentModule}` : 'Progress'}</span>
            <span className="text-accent">{progress}%</span>
          </div>
          <ProgressBar value={progress} height="h-2.5" />
        </div>

        {/* Live activity terminal — the focal "what is it doing right now" view. */}
        <div>
          <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">Live Activity</h2>
          <ScanTerminal logs={logs} height={420} />
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
      </main>
    </div>
  );
}
