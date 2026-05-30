import { Shield, LogOut, Plus, Activity } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth, useLogout } from '../hooks/useAuth.js';
import { Button } from '../components/ui.jsx';

// Landing dashboard. In Phase 1 this is intentionally minimal — it proves the
// authenticated shell (header, user identity, logout) works end to end. Phase 5
// fills it with scan stats, recent-scan cards, and the severity distribution
// chart from the PRD.

export default function Dashboard() {
  const { user } = useAuth();
  const logout = useLogout();
  const navigate = useNavigate();

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
          <div className="flex items-center gap-4">
            <span className="hidden font-mono text-xs text-fg-muted sm:inline">{user?.email}</span>
            <Button variant="ghost" onClick={handleLogout} loading={logout.isPending}>
              <LogOut className="h-4 w-4" aria-hidden="true" />
              <span className="hidden sm:inline">Logout</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="font-mono text-2xl font-bold text-fg">Dashboard</h1>
            <p className="mt-1 font-mono text-sm text-fg-muted">
              <span className="text-accent">$</span> ready to scan
              <span className="terminal-cursor" />
            </p>
          </div>
          <Button onClick={() => navigate('/scan/new')}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            New Scan
          </Button>
        </div>

        <div className="card flex flex-col items-center justify-center gap-3 p-12 text-center">
          <Activity className="h-10 w-10 text-fg-subtle" aria-hidden="true" />
          <p className="font-mono text-sm text-fg-muted">
            No scans yet. Start one to see live results here.
          </p>
          <p className="max-w-md font-mono text-xs text-fg-subtle">
            Scan stats, recent-scan history, and the severity distribution chart
            arrive in Phase 5. Authentication is wired and working.
          </p>
        </div>
      </main>
    </div>
  );
}
