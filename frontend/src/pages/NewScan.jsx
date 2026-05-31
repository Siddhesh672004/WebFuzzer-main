import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Target, AlertTriangle, ChevronDown } from 'lucide-react';
import { useMutation } from '@tanstack/react-query';
import { scanApi } from '../api/scans.js';
import { Button, Input, Alert } from '../components/ui.jsx';
import { ScanPresetSelector, SCAN_PRESETS } from '../components/ScanPresetSelector.jsx';

export default function NewScan() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [consented, setConsented] = useState(false);
  const [error, setError] = useState('');
  const [preset, setPreset] = useState('standard');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [rateLimit, setRateLimit] = useState(null);
  const [urlWarning, setUrlWarning] = useState('');

  const presetCfg = SCAN_PRESETS[preset]?.config || {};
  const effectiveConfig = { ...presetCfg, ...(rateLimit ? { rateLimit } : {}) };

  const start = useMutation({
    mutationFn: () => scanApi.create(url.trim(), true, effectiveConfig),
    onSuccess: (data) => navigate(`/scan/${data.scan.id}`),
    onError: (err) => setError(err.message || 'Failed to start scan'),
  });

  function validateUrl(value) {
    try {
      const u = new URL(value);
      // Warn (don't block) on private hosts — the backend gates these on SCAN_ALLOW_PRIVATE.
      if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(u.hostname)) {
        setUrlWarning('Private/local target — requires SCAN_ALLOW_PRIVATE=true on the worker.');
      } else {
        setUrlWarning('');
      }
      return true;
    } catch {
      return false;
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (!url.trim()) return setError('Enter a target URL.');
    if (!validateUrl(url.trim())) return setError('Enter a valid http(s) URL.');
    if (!consented) return setError('You must confirm authorization before scanning.');
    return start.mutate();
  }

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-center gap-3">
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-4 py-8">
        <h1 className="mb-2 font-mono text-2xl font-bold text-fg">New Scan</h1>
        <p className="mb-6 font-mono text-sm text-fg-muted"><span className="text-accent">$</span> configure and launch a scan</p>

        {error && <div className="mb-4"><Alert variant="error">{error}</Alert></div>}

        <form onSubmit={handleSubmit} noValidate className="space-y-6">
          <div className="card p-6">
            <Input
              id="target-url"
              label="Target URL"
              type="url"
              inputMode="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => { setUrl(e.target.value); validateUrl(e.target.value); }}
              autoFocus
            />
            {urlWarning && <p className="mt-2 font-mono text-xs text-severity-medium">{urlWarning}</p>}
          </div>

          {/* Preset selector */}
          <div>
            <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">Scan Depth</h2>
            <ScanPresetSelector value={preset} onChange={(id) => setPreset(id)} />
            <p className="mt-2 font-mono text-xs text-fg-subtle">{SCAN_PRESETS[preset]?.desc}</p>
            <p className="mt-1 font-mono text-[11px] text-fg-subtle">
              Tip: a scan can finish quickly when a site has few testable inputs (forms, query parameters) — that's normal, not a failure.
            </p>
          </div>

          {/* Advanced options */}
          <div className="card p-4">
            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className="flex w-full items-center justify-between font-mono text-sm text-fg"
            >
              <span>Advanced options</span>
              <ChevronDown className={`h-4 w-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
            </button>
            {showAdvanced && (
              <div className="mt-4 space-y-3">
                <label className="block font-mono text-xs text-fg-muted">
                  Rate limit (requests/sec): <span className="text-accent">{rateLimit ?? presetCfg.rateLimit}</span>
                  <input
                    type="range"
                    min="1"
                    max="50"
                    value={rateLimit ?? presetCfg.rateLimit ?? 10}
                    onChange={(e) => setRateLimit(Number(e.target.value))}
                    className="mt-1 w-full accent-accent"
                  />
                </label>
                <p className="font-mono text-[11px] leading-4 text-fg-subtle">
                  How many requests per second SmartFuzz sends to the target. Lower is gentler on the
                  server (and stealthier); higher is faster but heavier. The default is tuned per preset.
                </p>
                <div className="font-mono text-xs text-fg-muted">
                  Max depth <span className="text-accent">{presetCfg.maxDepth}</span> · up to{' '}
                  <span className="text-accent">{presetCfg.maxEndpoints}</span> endpoints
                </div>
                <p className="font-mono text-[11px] leading-4 text-fg-subtle">
                  Max depth = how many link-hops from the start page the crawler follows.
                  Endpoints = the cap on distinct pages/parameters it will test. Both come from the
                  selected preset.
                </p>
              </div>
            )}
          </div>

          <div className="card border-severity-medium/40 bg-severity-medium/5 p-6">
            <div className="mb-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-severity-medium" />
              <h2 className="font-mono text-sm font-bold text-severity-medium">Authorization Required</h2>
            </div>
            <p className="mb-4 font-mono text-xs text-fg-muted">
              SmartFuzz is an active security scanner. Only scan systems you own or have explicit written permission to test.
              Unauthorized scanning may be illegal under the IT Act 2000, CFAA, and equivalent laws.
            </p>
            <label className="flex cursor-pointer items-start gap-3">
              <input
                type="checkbox"
                checked={consented}
                onChange={(e) => setConsented(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-accent"
              />
              <span className="font-mono text-sm text-fg">
                I confirm I own this target or have explicit written permission to scan it.
              </span>
            </label>
          </div>

          <div className="flex items-center gap-4">
            <Button type="submit" loading={start.isPending} disabled={!consented}>
              <Target className="h-4 w-4" />
              Start Scan
            </Button>
            <Button type="button" variant="ghost" onClick={() => navigate('/dashboard')}>
              Cancel
            </Button>
          </div>
        </form>
      </main>
    </div>
  );
}
