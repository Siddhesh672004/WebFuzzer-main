import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Target, AlertTriangle, ChevronDown, Beaker, Globe, KeyRound } from 'lucide-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { scanApi, metaApi } from '../api/scans.js';
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

  // Opt-in toggles + authenticated-crawl config.
  const [aggressiveMode, setAggressiveMode] = useState(false);
  const [headlessCrawl, setHeadlessCrawl] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [authType, setAuthType] = useState('none');
  const [cookieStr, setCookieStr] = useState('');
  const [headerStr, setHeaderStr] = useState('');
  const [loginUrl, setLoginUrl] = useState('');
  const [usernameField, setUsernameField] = useState('username');
  const [passwordField, setPasswordField] = useState('password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Demo mode (P6.2): pre-fill an authorized public test target + show a banner.
  const { data: meta } = useQuery({ queryKey: ['meta'], queryFn: metaApi.get, staleTime: 300_000 });
  useEffect(() => {
    if (meta?.demoMode && meta.demoTarget && !url) {
      setUrl(meta.demoTarget);
      validateUrl(meta.demoTarget);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [meta]);

  const presetCfg = SCAN_PRESETS[preset]?.config || {};

  function buildAuthConfig() {
    if (authType === 'none') return null;
    if (authType === 'cookie') {
      const customCookies = cookieStr
        .split(';').map((s) => s.trim()).filter(Boolean)
        .map((pair) => {
          const i = pair.indexOf('=');
          return i > 0 ? { name: pair.slice(0, i).trim(), value: pair.slice(i + 1).trim() } : null;
        })
        .filter(Boolean);
      return { type: 'cookie', customCookies };
    }
    if (authType === 'headers') {
      const customHeaders = {};
      headerStr.split('\n').map((s) => s.trim()).filter(Boolean).forEach((line) => {
        const i = line.indexOf(':');
        if (i > 0) customHeaders[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      });
      return { type: 'headers', customHeaders };
    }
    return { type: 'form_fill', loginUrl, usernameField, passwordField, username, password };
  }

  const effectiveConfig = {
    ...presetCfg,
    ...(rateLimit ? { rateLimit } : {}),
    aggressiveMode,
    headlessCrawl,
    ...(authType !== 'none' ? { auth: buildAuthConfig() } : {}),
  };

  const start = useMutation({
    mutationFn: () => scanApi.create(url.trim(), true, effectiveConfig),
    onSuccess: (data) => navigate(`/scan/${data.scan.id}`),
    onError: (err) => setError(err.message || 'Failed to start scan'),
  });

  function validateUrl(value) {
    try {
      const u = new URL(value);
      if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(u.hostname)) {
        setUrlWarning('Private/local target: requires SCAN_ALLOW_PRIVATE=true on the worker.');
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

      <main className="mx-auto max-w-3xl px-4 py-8 animate-slide-up">
        <h1 className="mb-2 font-display text-3xl tracking-tightest text-fg">New scan</h1>
        <p className="mb-6 font-mono text-sm text-fg-muted"><span className="text-accent">$</span> configure and launch a scan</p>

        {meta?.demoMode && (
          <div className="mb-4 flex items-start gap-3 rounded-xl border border-accent/40 bg-accent/5 px-4 py-3">
            <Beaker className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
            <p className="text-sm text-fg-muted">
              <span className="font-semibold text-fg">Demo mode.</span> The target is pre-filled with the
              authorized public test site <span className="font-mono text-accent">{meta.demoTarget}</span>.
            </p>
          </div>
        )}

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
            <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wide text-fg-muted">Scan depth</h2>
            <ScanPresetSelector value={preset} onChange={(id) => setPreset(id)} />
            <p className="mt-2 text-sm text-fg-subtle">{SCAN_PRESETS[preset]?.desc}</p>
            <p className="mt-1 text-[13px] text-fg-subtle">
              Tip: a scan can finish quickly when a site has few testable inputs (forms, query parameters). That's normal, not a failure.
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
              <div className="mt-4 space-y-4">
                <label className="block font-mono text-xs text-fg-muted">
                  Rate limit (requests/sec): <span className="text-accent">{rateLimit ?? presetCfg.rateLimit}</span>
                  <input
                    type="range" min="1" max="50"
                    value={rateLimit ?? presetCfg.rateLimit ?? 10}
                    onChange={(e) => setRateLimit(Number(e.target.value))}
                    className="mt-1 w-full accent-accent"
                  />
                </label>
                <div className="font-mono text-xs text-fg-muted">
                  Max depth <span className="text-accent">{presetCfg.maxDepth}</span> · up to{' '}
                  <span className="text-accent">{presetCfg.maxEndpoints}</span> endpoints
                </div>

                {/* Headless crawl toggle (P2.1) */}
                <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border-muted p-3">
                  <input type="checkbox" checked={headlessCrawl} onChange={(e) => setHeadlessCrawl(e.target.checked)} className="mt-0.5 h-4 w-4 accent-accent" />
                  <span className="text-sm text-fg">
                    <span className="inline-flex items-center gap-1.5 font-medium"><Globe className="h-3.5 w-3.5 text-fg-muted" /> Headless (browser) crawl</span>
                    <span className="mt-0.5 block text-[13px] text-fg-subtle">Render JavaScript to discover SPA routes &amp; XHR endpoints. Slower; falls back to the static crawler automatically.</span>
                  </span>
                </label>

                {/* Aggressive mode toggle (P0.4) */}
                <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-severity-high/30 bg-severity-high/5 p-3">
                  <input type="checkbox" checked={aggressiveMode} onChange={(e) => setAggressiveMode(e.target.checked)} className="mt-0.5 h-4 w-4 accent-accent" />
                  <span className="text-sm text-fg">
                    <span className="inline-flex items-center gap-1.5 font-medium text-severity-high"><AlertTriangle className="h-3.5 w-3.5" /> Aggressive mode</span>
                    <span className="mt-0.5 block text-[13px] text-fg-subtle">Submit real default-credential login attempts and intrusive auth probes. Use only on targets you fully control.</span>
                  </span>
                </label>
              </div>
            )}
          </div>

          {/* Authenticated crawl (P2.2) */}
          <div className="card p-4">
            <button
              type="button"
              onClick={() => setShowAuth((v) => !v)}
              className="flex w-full items-center justify-between font-mono text-sm text-fg"
            >
              <span className="inline-flex items-center gap-2"><KeyRound className="h-4 w-4 text-fg-muted" /> Authenticated crawl{authType !== 'none' && <span className="chip bg-accent/15 text-accent">{authType}</span>}</span>
              <ChevronDown className={`h-4 w-4 transition-transform ${showAuth ? 'rotate-180' : ''}`} />
            </button>
            {showAuth && (
              <div className="mt-4 space-y-3">
                <div className="flex flex-wrap gap-2">
                  {['none', 'cookie', 'headers', 'form_fill'].map((t) => (
                    <button
                      key={t} type="button" onClick={() => setAuthType(t)}
                      className={`rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors ${authType === t ? 'border-accent bg-accent/10 text-accent' : 'border-border text-fg-muted hover:border-fg-subtle'}`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
                {authType === 'cookie' && (
                  <Input id="auth-cookies" label="Cookies (name=value; name2=value2)" placeholder="session=abc123; role=admin" value={cookieStr} onChange={(e) => setCookieStr(e.target.value)} />
                )}
                {authType === 'headers' && (
                  <label className="block">
                    <span className="mb-1 block font-mono text-xs text-fg-muted">Headers (one per line: Name: value)</span>
                    <textarea rows={3} value={headerStr} onChange={(e) => setHeaderStr(e.target.value)} placeholder="Authorization: Bearer eyJ..." className="w-full rounded-lg border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent" />
                  </label>
                )}
                {authType === 'form_fill' && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Input id="auth-loginurl" label="Login URL" placeholder="https://site/login" value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} />
                    <Input id="auth-userfield" label="Username field name" value={usernameField} onChange={(e) => setUsernameField(e.target.value)} />
                    <Input id="auth-username" label="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
                    <Input id="auth-passfield" label="Password field name" value={passwordField} onChange={(e) => setPasswordField(e.target.value)} />
                    <Input id="auth-password" label="Password (never stored)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                )}
                {authType === 'form_fill' && (
                  <p className="text-[13px] text-fg-subtle">The password is used only during this scan's login and is never written to the database: it travels in the job payload and is discarded. Form-fill login requires the headless crawler.</p>
                )}
              </div>
            )}
          </div>

          <div className="card border-severity-medium/40 bg-severity-medium/5 p-6">
            <div className="mb-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-severity-medium" />
              <h2 className="font-mono text-sm font-bold text-severity-medium">Authorization required</h2>
            </div>
            <p className="mb-4 text-sm text-fg-muted">
              SmartFuzz is an active security scanner. Only scan systems you own or have explicit written permission to test.
              Unauthorized scanning may be illegal under the IT Act 2000, CFAA, and equivalent laws.
            </p>
            <label className="flex cursor-pointer items-start gap-3">
              <input type="checkbox" checked={consented} onChange={(e) => setConsented(e.target.checked)} className="mt-0.5 h-4 w-4 accent-accent" />
              <span className="text-sm text-fg">
                I confirm I own this target or have explicit written permission to scan it.
              </span>
            </label>
          </div>

          <div className="flex items-center gap-4">
            <Button type="submit" loading={start.isPending} disabled={!consented}>
              <Target className="h-4 w-4" />
              Start scan
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
