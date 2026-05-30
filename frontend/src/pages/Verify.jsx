import { Shield } from 'lucide-react';

// Placeholder Verify page — proves the shell, theme, and lazy routing work.
// Phase 1 replaces this with the real OTP email → code → JWT flow wired to
// authApi (src/api/client.js).

export default function Verify() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="card w-full max-w-md p-8">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="h-8 w-8 text-accent" aria-hidden="true" />
          <h1 className="font-mono text-2xl font-bold text-fg">
            Smart<span className="text-accent">Fuzz</span>
          </h1>
        </div>

        <p className="font-mono text-sm text-fg-muted">
          <span className="text-accent">$</span> zero-cost web vulnerability scanner
          <span className="terminal-cursor" />
        </p>

        <div className="mt-8 rounded border border-border-muted bg-bg-inset p-4">
          <p className="text-sm text-fg-subtle">
            Email-OTP verification arrives in Phase 1. This shell confirms the
            theme, routing, and build are wired up.
          </p>
        </div>
      </div>
    </main>
  );
}
