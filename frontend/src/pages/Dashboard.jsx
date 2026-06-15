import { useNavigate } from 'react-router-dom';
import { Shield, LogOut, Plus, Activity, BarChart3 } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useAuth, useLogout } from '../hooks/useAuth.js';
import { scanApi } from '../api/scans.js';
import { Button } from '../components/ui.jsx';
import { SEVERITY_HEX, STATUS_HEX } from '../lib/palette.js';

// Hex mirrors of the OKLCH severity/status tokens (see lib/palette.js):
// running pulses phosphor green, completed settles dim green.
const SEV_COLOR = SEVERITY_HEX;
const STATUS_COLOR = STATUS_HEX;

export default function Dashboard() {
  const { user } = useAuth();
  const logout = useLogout();
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scanApi.list(1, 20),
    refetchInterval: 10000,
  });

  const scans = data?.scans || [];
  const runningScans = scans.filter((s) => s.status === 'running');

  async function handleLogout() {
    await logout.mutateAsync();
    navigate('/verify', { replace: true });
  }

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-bg-subtle">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-accent" aria-hidden="true" />
            <span className="font-mono text-lg font-bold text-fg">
              Smart<span className="text-accent">Fuzz</span>
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden font-mono text-xs text-fg-muted sm:inline">{user?.email}</span>
            <Button variant="ghost" onClick={() => navigate('/benchmark')}>
              <BarChart3 className="h-4 w-4" aria-hidden="true" />
              <span className="hidden sm:inline">Benchmark</span>
            </Button>
            <Button variant="ghost" onClick={handleLogout} loading={logout.isPending}>
              <LogOut className="h-4 w-4" aria-hidden="true" />
              <span className="hidden sm:inline">Logout</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8 animate-slide-up">
        <div className="mb-8 flex items-end justify-between gap-4">
          <div>
            <h1 className="font-display text-3xl tracking-tightest text-fg sm:text-4xl">Dashboard</h1>
            <p className="mt-1 font-mono text-sm text-fg-muted">
              <span className="text-accent">$</span> {runningScans.length > 0 ? `${runningScans.length} scan(s) running` : 'ready to scan'}
              <span className="terminal-cursor" />
            </p>
          </div>
          <Button onClick={() => navigate('/scan/new')}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            New scan
          </Button>
        </div>

        {/* Stat bar — one panel, segmented, instead of four identical cards. */}
        <div className="mb-8 grid grid-cols-2 divide-y divide-border rounded-xl border border-border bg-bg-subtle sm:grid-cols-4 sm:divide-x sm:divide-y-0">
          {[
            { label: 'Total scans', value: data?.total ?? 0 },
            { label: 'Running', value: runningScans.length },
            { label: 'Completed', value: scans.filter((s) => s.status === 'completed').length },
            { label: 'Targets', value: new Set(scans.map((s) => s.targetDomain)).size },
          ].map(({ label, value }) => (
            <div key={label} className="px-5 py-4">
              <div className="font-mono text-3xl text-fg">{value}</div>
              <div className="mt-1 text-[13px] uppercase tracking-wide text-fg-subtle">{label}</div>
            </div>
          ))}
        </div>

        {/* Scan list */}
        <div className="card">
          <div className="border-b border-border px-4 py-3">
            <h2 className="font-mono text-sm font-bold text-fg">Recent Scans</h2>
          </div>
          {isLoading ? (
            <div className="p-8 text-center font-mono text-sm text-fg-muted"><span className="terminal-cursor">loading</span></div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center">
              <Activity className="mx-auto mb-3 h-10 w-10 text-fg-subtle" />
              <p className="font-mono text-sm text-fg-muted">No scans yet. Start one to see results here.</p>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {scans.map((s) => (
                <div
                  key={s.id}
                  className="flex items-center gap-4 px-4 py-3 hover:bg-bg-subtle cursor-pointer"
                  onClick={() => navigate(s.status === 'running' ? `/scan/${s.id}` : `/results/${s.id}`)}
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-fg truncate">{s.targetUrl}</p>
                    <p className="font-mono text-xs text-fg-muted">
                      #{s.scanNumber} · {new Date(s.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {s.status === 'completed' && (
                      <div className="flex gap-1">
                        {['critical', 'high', 'medium'].map((sev) => s.stats?.[sev] > 0 && (
                          <span key={sev} className="font-mono text-xs font-bold" style={{ color: SEV_COLOR[sev] }}>
                            {s.stats[sev]}{sev[0].toUpperCase()}
                          </span>
                        ))}
                      </div>
                    )}
                    <span
                      className="font-mono text-xs font-bold capitalize"
                      style={{ color: STATUS_COLOR[s.status] || STATUS_COLOR.pending }}
                    >
                      {s.status}
                    </span>
                    {s.status === 'completed' && (
                      <button
                        className="font-mono text-xs text-accent hover:underline"
                        onClick={(e) => { e.stopPropagation(); navigate(`/compare/${s.targetDomain}`); }}
                      >
                        compare
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
