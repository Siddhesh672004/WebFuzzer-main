import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Target, AlertTriangle } from 'lucide-react';
import { useMutation } from '@tanstack/react-query';
import { scanApi } from '../api/scans.js';
import { Button, Input, Alert } from '../components/ui.jsx';

export default function NewScan() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [consented, setConsented] = useState(false);
  const [error, setError] = useState('');

  const start = useMutation({
    mutationFn: () => scanApi.create(url.trim(), true),
    onSuccess: (data) => navigate(`/scan/${data.scan.id}`),
    onError: (err) => setError(err.message || 'Failed to start scan'),
  });

  function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (!url.trim()) return setError('Enter a target URL.');
    try { new URL(url.trim()); } catch { return setError('Enter a valid http(s) URL.'); }
    if (!consented) return setError('You must confirm authorization before scanning.');
    start.mutate();
  }

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-center gap-3">
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-4 py-8">
        <h1 className="mb-2 font-mono text-2xl font-bold text-fg">New Scan</h1>
        <p className="mb-6 font-mono text-sm text-fg-muted"><span className="text-accent">$</span> enter a target URL to begin</p>

        {error && <div className="mb-4"><Alert variant="error">{error}</Alert></div>}

        <form onSubmit={handleSubmit} noValidate className="space-y-6">
          <div className="card p-6">
            <Input
              id="target-url"
              label="Target URL"
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              autoFocus
            />
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
