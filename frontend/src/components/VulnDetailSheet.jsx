import { useState } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Copy, Check, CheckCircle2, ShieldCheck, Loader2, Key, Camera } from 'lucide-react';
import { Badge } from './ui/Badge.jsx';
import { BottomSheet } from './ui/BottomSheet.jsx';
import { CVSSMeter } from './CVSSMeter.jsx';
import { FixGuidePanel } from './FixGuidePanel.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';
import { useIsMobile } from '../hooks/useMediaQuery.jsx';

// VulnDetailSheet — full finding detail. Desktop: a 480px panel sliding in from
// the right. Mobile: a bottom sheet. Both render the same body: CVSS breakdown,
// payload + evidence, request/response, fix guide, and remediation actions.

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const copy = () => {
    navigator.clipboard?.writeText(String(value)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-wide text-fg-subtle">{label}</span>
        <button onClick={copy} className="text-fg-subtle hover:text-fg" aria-label={`Copy ${label}`}>
          {copied ? <Check size={12} className="text-accent" /> : <Copy size={12} />}
        </button>
      </div>
      <pre className="overflow-x-auto rounded-md border border-border bg-bg-inset p-2.5 font-mono text-xs text-fg-muted">
        <code>{value}</code>
      </pre>
    </div>
  );
}

function SheetBody({ vuln, fixGuide, onMarkFixed, onVerify, busy }) {
  const verified = vuln.verificationStatus === 'verified_fixed';
  const persists = vuln.verificationStatus === 'verified_persists';
  const isSecret = vuln.type === 'exposed_secret';
  const location = isSecret ? (vuln.jsFileUrl || vuln.url) : vuln.url;

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Badge severity={vuln.severity} score={vuln.cvssScore} />
        <span className="font-mono text-xs text-fg-muted">
          {location}
          {isSecret && vuln.lineNumber ? ` · line ${vuln.lineNumber}` : vuln.param ? ` · ${vuln.param}` : ''}
        </span>
      </div>

      <CVSSMeter vector={vuln.cvssVector} score={vuln.cvssScore} />

      {/* Exposed-secret specifics */}
      {isSecret && (
        <div className="rounded-md border border-severity-medium/40 bg-severity-medium/5 p-3">
          <div className="mb-1 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide text-severity-medium">
            <Key size={12} /> Exposed Secret
          </div>
          {vuln.secretType && (
            <div className="font-mono text-sm text-fg">{vuln.secretType}</div>
          )}
          {vuln.matchPreview && (
            <pre className="mt-2 overflow-x-auto rounded border border-border bg-bg-inset p-2 font-mono text-xs text-fg-muted"><code>{vuln.matchPreview}</code></pre>
          )}
          <p className="mt-2 font-mono text-[11px] text-fg-subtle">
            Full value is never stored, only this masked preview. Rotate this credential immediately.
          </p>
        </div>
      )}

      {vuln.payload && <CopyField label="Payload" value={vuln.payload} />}
      {vuln.evidence && (
        <div>
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wide text-fg-subtle">Evidence</div>
          <p className="rounded-md border border-accent/30 bg-accent/5 p-2.5 font-mono text-xs text-fg">{vuln.evidence}</p>
        </div>
      )}

      {/* Screenshot evidence (Puppeteer capture for xss/open_redirect) */}
      {vuln.screenshotFile && (
        <div>
          <div className="mb-1 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide text-fg-subtle">
            <Camera size={12} /> Visual Evidence
          </div>
          {vuln.screenshotDialogFired && (
            <div className="mb-2 rounded-md border border-severity-critical/40 bg-severity-critical/10 px-2.5 py-1.5 font-mono text-xs text-severity-critical">
              ⚠ JavaScript dialog fired: <code>{vuln.screenshotDialogMessage || 'XSS confirmed'}</code>
            </div>
          )}
          <div className="relative overflow-hidden rounded-md border border-border">
            <img
              src={`/api/screenshots/${vuln.screenshotFile}`}
              alt="Vulnerability screenshot evidence"
              className="block w-full cursor-pointer"
              onClick={() => window.open(`/api/screenshots/${vuln.screenshotFile}`, '_blank')}
              onError={(e) => { e.currentTarget.parentElement.style.display = 'none'; }}
            />
            <a
              href={`/api/screenshots/${vuln.screenshotFile}`}
              download
              className="absolute bottom-2 right-2 rounded border border-border bg-bg-surface px-2 py-1 font-mono text-xs text-fg-muted hover:text-fg"
            >
              ↓ Download
            </a>
          </div>
        </div>
      )}

      {vuln.request && (vuln.request.url || vuln.request.method) && (
        <CopyField
          label="HTTP Request"
          value={`${vuln.request.method || 'GET'} ${vuln.request.url || vuln.url}${vuln.request.body ? `\n\n${vuln.request.body}` : ''}`}
        />
      )}
      {vuln.response?.bodyExcerpt && (
        <CopyField label={`HTTP Response (${vuln.response.statusCode || '?'})`} value={vuln.response.bodyExcerpt.slice(0, 2000)} />
      )}

      {fixGuide && (
        <div className="border-t border-border pt-4">
          <FixGuidePanel fixGuide={fixGuide} cwe={vuln.cwe} />
        </div>
      )}

      {/* Remediation actions */}
      <div className="flex flex-wrap gap-2 border-t border-border pt-4">
        <button
          onClick={() => onMarkFixed?.(!vuln.markedFixedByUser)}
          className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-2 font-mono text-xs ${
            vuln.markedFixedByUser ? 'border-accent text-accent' : 'border-border text-fg hover:bg-bg-subtle'
          }`}
        >
          <CheckCircle2 size={14} /> {vuln.markedFixedByUser ? 'Marked Fixed' : 'Mark as Fixed'}
        </button>
        <button
          onClick={() => onVerify?.()}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md bg-accent-dim px-3 py-2 font-mono text-xs text-white hover:bg-accent-glow disabled:opacity-50"
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />} Verify Fix
        </button>
        {verified && <span className="inline-flex items-center gap-1 font-mono text-xs text-accent"><CheckCircle2 size={14} /> Verified Fixed</span>}
        {persists && <span className="font-mono text-xs text-severity-high">Still vulnerable</span>}
      </div>
    </div>
  );
}

export function VulnDetailSheet({ vuln, fixGuide, isOpen, onClose, onMarkFixed, onVerify, busy }) {
  const isMobile = useIsMobile();
  if (!vuln) return null;

  if (isMobile) {
    return (
      <BottomSheet isOpen={isOpen} onClose={onClose} title={getVulnLabel(vuln.type)}>
        <SheetBody vuln={vuln} fixGuide={fixGuide} onMarkFixed={onMarkFixed} onVerify={onVerify} busy={busy} />
      </BottomSheet>
    );
  }

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div className="fixed inset-0 z-50" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
          <motion.aside
            role="dialog"
            aria-modal="true"
            className="absolute right-0 top-0 flex h-full w-full max-w-[480px] flex-col border-l border-border bg-bg-subtle"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 320, damping: 34 }}
          >
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h3 className="font-mono text-sm font-semibold text-fg">{getVulnLabel(vuln.type)}</h3>
              <button onClick={onClose} className="text-fg-muted hover:text-fg" aria-label="Close"><X size={18} /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              <SheetBody vuln={vuln} fixGuide={fixGuide} onMarkFixed={onMarkFixed} onVerify={onVerify} busy={busy} />
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export default VulnDetailSheet;
