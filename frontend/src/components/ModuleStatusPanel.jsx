import { Globe, Eye, FileSearch, Cpu, Crosshair, KeyRound, Key, Check, X, Loader2, Circle } from 'lucide-react';

// ModuleStatusPanel — the scanning modules with live status. Status comes
// from SSE 'module' events keyed by module name. Running modules pulse.

const MODULES = [
  { key: 'crawler', label: 'Crawler', Icon: Globe },
  { key: 'passive', label: 'Passive Analysis', Icon: Eye },
  { key: 'exposed', label: 'Exposed Files', Icon: FileSearch },
  { key: 'tech', label: 'Tech Fingerprint', Icon: Cpu },
  { key: 'fuzzer', label: 'Payload Fuzzer', Icon: Crosshair },
  { key: 'auth', label: 'Auth Tests', Icon: KeyRound },
  { key: 'jsSecrets', label: 'JS Secret Scanner', Icon: Key },
];

function StatusDot({ status }) {
  if (status === 'completed') return <Check size={14} className="text-accent" />;
  if (status === 'failed') return <X size={14} className="text-severity-critical" />;
  if (status === 'running') return <Loader2 size={14} className="animate-spin text-severity-low" />;
  if (status === 'degraded') return <Circle size={10} className="fill-severity-medium text-severity-medium" />;
  return <Circle size={10} className="text-fg-subtle" />;
}

export function ModuleStatusPanel({ modules = {}, compact = false }) {
  if (compact) {
    return (
      <div className="flex flex-wrap gap-2">
        {MODULES.map(({ key, label, Icon }) => {
          const m = modules[key] || {};
          const running = m.status === 'running';
          return (
            <div
              key={key}
              title={`${label}: ${m.status || 'pending'}`}
              className={`flex items-center gap-1.5 rounded-md border border-border bg-bg-subtle px-2 py-1 ${running ? 'animate-pulse-glow' : ''}`}
            >
              <Icon size={13} className="text-fg-muted" />
              <StatusDot status={m.status} />
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="card divide-y divide-border">
      {MODULES.map(({ key, label, Icon }) => {
        const m = modules[key] || {};
        const running = m.status === 'running';
        return (
          <div key={key} className={`flex items-center gap-3 px-4 py-3 ${running ? 'bg-bg-subtle' : ''}`}>
            <div className={`flex h-8 w-8 items-center justify-center rounded-md border border-border ${running ? 'animate-pulse-glow border-accent/40' : ''}`}>
              <Icon size={16} className={running ? 'text-accent' : 'text-fg-muted'} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="font-mono text-sm text-fg">{label}</div>
              {m.summary && <div className="truncate font-mono text-xs text-fg-subtle">{m.summary}</div>}
            </div>
            <StatusDot status={m.status} />
          </div>
        );
      })}
    </div>
  );
}

export default ModuleStatusPanel;
