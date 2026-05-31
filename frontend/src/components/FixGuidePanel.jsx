import { useState } from 'react';
import { Tabs } from './ui/Tabs.jsx';
import { Copy, Check, BookOpen, Wrench, ShieldCheck, ExternalLink } from 'lucide-react';

// FixGuidePanel — renders a fix guide from the worker knowledge base. The KB
// shape is { what, why, steps[], before, after, verify, ref }. Three tabs map to
// the PRD's 3-layer model: WHAT IS THIS / HOW TO FIX / VERIFY.

function CodeBlock({ code, label }) {
  const [copied, setCopied] = useState(false);
  if (!code) return null;
  const copy = () => {
    navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div className="relative">
      {label && <div className="mb-1 font-mono text-[10px] uppercase tracking-wide text-fg-subtle">{label}</div>}
      <pre className="overflow-x-auto rounded-md border border-border bg-bg-inset p-3 font-mono text-xs text-accent">
        <code>{code}</code>
      </pre>
      <button
        onClick={copy}
        className="absolute right-2 top-7 text-fg-subtle hover:text-fg"
        aria-label="Copy code"
      >
        {copied ? <Check size={14} className="text-accent" /> : <Copy size={14} />}
      </button>
    </div>
  );
}

export function FixGuidePanel({ fixGuide, cwe, className = '' }) {
  const [tab, setTab] = useState('what');
  if (!fixGuide) return null;

  const tabs = [
    { id: 'what', label: 'WHAT IS THIS', icon: BookOpen },
    { id: 'fix', label: 'HOW TO FIX', icon: Wrench },
    { id: 'verify', label: 'VERIFY', icon: ShieldCheck },
  ];

  return (
    <div className={className}>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <div className="pt-3">
        {tab === 'what' && (
          <div className="space-y-3 font-mono text-sm">
            <p className="text-fg">{fixGuide.what}</p>
            <div className="rounded-md border border-severity-high/30 bg-severity-high/10 p-3">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-severity-high">What an attacker can do</div>
              <p className="text-fg-muted">{fixGuide.why}</p>
            </div>
          </div>
        )}

        {tab === 'fix' && (
          <div className="space-y-3">
            {Array.isArray(fixGuide.steps) && (
              <ol className="list-inside list-decimal space-y-1 font-mono text-sm text-fg-muted">
                {fixGuide.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            )}
            <CodeBlock code={fixGuide.before} label="Vulnerable" />
            <CodeBlock code={fixGuide.after} label="Fixed" />
          </div>
        )}

        {tab === 'verify' && (
          <div className="space-y-3 font-mono text-sm">
            <p className="text-fg-muted">{fixGuide.verify}</p>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between border-t border-border pt-3 font-mono text-xs">
        {cwe && <span className="text-fg-subtle">CWE: {cwe}</span>}
        {fixGuide.ref && (
          <a
            href={fixGuide.ref}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-severity-low hover:underline"
          >
            OWASP reference <ExternalLink size={12} />
          </a>
        )}
      </div>
    </div>
  );
}

export default FixGuidePanel;
