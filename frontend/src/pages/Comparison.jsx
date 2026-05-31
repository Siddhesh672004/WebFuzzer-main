import { useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useQueries } from '@tanstack/react-query';
import { Shield, ArrowLeft } from 'lucide-react';
import { scanApi } from '../api/scans.js';
import { SecurityScoreChart } from '../components/SecurityScoreChart.jsx';
import { ComparisonTable } from '../components/ComparisonTable.jsx';

// Cross-scan comparison. Fetches every scan for the domain, then each scan's
// findings, and computes per-signature status across scans client-side (the
// worker's compareScans runs server-side for reports; here we mirror its rules
// for the live table). Status per scan N for a signature:
//   present in N            → VULNERABLE
//   absent in N, present <N → FIXED
//   present in N, absent N-1, never before → NEW
//   present in N, absent N-1, present earlier → REGRESSED

function buildRows(scans, vulnsByScan) {
  const ordered = [...scans].sort((a, b) => a.scanNumber - b.scanNumber);
  const bySig = new Map();

  for (const scan of ordered) {
    for (const v of vulnsByScan[scan.id] || []) {
      if (!bySig.has(v.signature)) {
        bySig.set(v.signature, { type: v.type, url: v.url, param: v.param, signature: v.signature, present: new Set() });
      }
      bySig.get(v.signature).present.add(scan.scanNumber);
    }
  }

  const rows = [];
  for (const row of bySig.values()) {
    const statusByScan = {};
    let seenBefore = false;
    for (const scan of ordered) {
      const n = scan.scanNumber;
      const here = row.present.has(n);
      if (here) {
        const prev = ordered[ordered.findIndex((s) => s.scanNumber === n) - 1];
        const inPrev = prev && row.present.has(prev.scanNumber);
        if (!seenBefore) statusByScan[n] = 'NEW';
        else if (inPrev) statusByScan[n] = 'VULNERABLE';
        else statusByScan[n] = 'REGRESSED';
        seenBefore = true;
      } else if (seenBefore) {
        statusByScan[n] = 'FIXED';
      }
    }
    rows.push({ ...row, statusByScan });
  }
  return rows;
}

export default function Comparison() {
  const { domain } = useParams();
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ['scans', 'domain', domain],
    queryFn: () => scanApi.byDomain(domain),
    enabled: !!domain,
  });

  const scans = useMemo(() => (data?.scans || []).filter((s) => s.status === 'completed'), [data]);

  // Fetch vulnerabilities for every completed scan in parallel.
  const vulnQueries = useQueries({
    queries: scans.map((s) => ({
      queryKey: ['scan', s.id, 'vulns'],
      queryFn: () => scanApi.vulnerabilities(s.id),
      enabled: scans.length > 0,
    })),
  });

  const vulnsByScan = useMemo(() => {
    const map = {};
    scans.forEach((s, i) => { map[s.id] = vulnQueries[i]?.data?.vulnerabilities || []; });
    return map;
  }, [scans, vulnQueries]);

  const rows = useMemo(() => buildRows(scans, vulnsByScan), [scans, vulnsByScan]);

  const history = scans.map((s) => ({
    scanNumber: s.scanNumber,
    score: s.stats?.securityScore ?? 100,
    date: new Date(s.createdAt).toLocaleDateString(),
  }));
  const scoresByScan = Object.fromEntries(scans.map((s) => [s.scanNumber, s.stats?.securityScore ?? 100]));

  // Summary counts from the latest scan column.
  const summary = useMemo(() => {
    const last = scans[scans.length - 1]?.scanNumber;
    const c = { fixed: 0, persists: 0, new: 0, regressed: 0 };
    for (const r of rows) {
      const s = r.statusByScan[last];
      if (s === 'FIXED') c.fixed += 1;
      else if (s === 'VULNERABLE') c.persists += 1;
      else if (s === 'NEW') c.new += 1;
      else if (s === 'REGRESSED') c.regressed += 1;
    }
    return c;
  }, [rows, scans]);

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center font-mono text-fg-muted"><span className="terminal-cursor">loading</span></div>;
  }

  return (
    <div className="min-h-screen bg-bg pb-16 sm:pb-0">
      <header className="border-b border-border bg-bg-subtle px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center gap-3">
          <button onClick={() => navigate('/dashboard')} className="text-fg-muted hover:text-fg" aria-label="Back">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <Shield className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-5 px-4 py-6">
        <div>
          <h1 className="font-mono text-xl font-bold text-fg">{domain}</h1>
          <p className="font-mono text-sm text-fg-muted">{scans.length} scan{scans.length !== 1 ? 's' : ''} analyzed</p>
        </div>

        {scans.length === 0 ? (
          <div className="card p-8 text-center font-mono text-sm text-fg-subtle">No completed scans for this domain yet.</div>
        ) : scans.length === 1 ? (
          <>
            <SecurityScoreChart history={history} />
            <div className="card p-6 text-center font-mono text-sm text-fg-muted">
              Run another scan after fixing issues to see a fixed/persists comparison.
            </div>
          </>
        ) : (
          <>
            <SecurityScoreChart history={history} />

            {/* Summary cards */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { label: 'Fixed', value: summary.fixed, cls: 'text-accent' },
                { label: 'Persists', value: summary.persists, cls: 'text-severity-high' },
                { label: 'New', value: summary.new, cls: 'text-severity-low' },
                { label: 'Regressed', value: summary.regressed, cls: 'text-severity-critical' },
              ].map((c) => (
                <div key={c.label} className="card p-4 text-center">
                  <div className={`font-mono text-2xl font-bold ${c.cls}`}>{c.value}</div>
                  <div className="font-mono text-xs text-fg-muted">{c.label}</div>
                </div>
              ))}
            </div>

            <ComparisonTable scans={scans} rows={rows} scoresByScan={scoresByScan} />
          </>
        )}
      </main>
    </div>
  );
}
