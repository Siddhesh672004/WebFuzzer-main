import { useState } from 'react';
import { Badge } from './ui/Badge.jsx';
import { getVulnLabel } from '../lib/vulnLabels.js';

// ComparisonTable — cross-scan diff. `rows` come from the worker comparison
// engine: { type, url, param, statusByScan: { [scanNumber]: STATUS } }. Status
// values: VULNERABLE | FIXED | NEW | REGRESSED. First column is sticky so the
// scan columns scroll horizontally on mobile. A score row pins to the bottom.

const FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'fixed', label: 'Fixed', status: 'FIXED' },
  { id: 'persists', label: 'Persists', status: 'VULNERABLE' },
  { id: 'new', label: 'New', status: 'NEW' },
  { id: 'regressed', label: 'Regressed', status: 'REGRESSED' },
];

const STATUS_TO_BADGE = {
  FIXED: { status: 'fixed' },
  VULNERABLE: { status: 'persists' },
  NEW: { status: 'new' },
  REGRESSED: { status: 'regressed' },
};

function latestStatus(row, scans) {
  for (let i = scans.length - 1; i >= 0; i -= 1) {
    const s = row.statusByScan[scans[i].scanNumber];
    if (s) return s;
  }
  return null;
}

export function ComparisonTable({ scans = [], rows = [], scoresByScan = {} }) {
  const [filter, setFilter] = useState('all');

  const visible = rows.filter((row) => {
    if (filter === 'all') return true;
    const want = FILTERS.find((f) => f.id === filter)?.status;
    return latestStatus(row, scans) === want;
  });

  return (
    <div className="card overflow-hidden">
      {/* Filter chips */}
      <div className="flex flex-wrap gap-1.5 border-b border-border p-3">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            onClick={() => setFilter(f.id)}
            className={`rounded-full border px-3 py-1 font-mono text-xs ${
              filter === f.id ? 'border-accent bg-accent/10 text-accent' : 'border-border text-fg-muted hover:text-fg'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b border-border">
              <th className="sticky left-0 z-10 bg-bg-subtle px-3 py-2 text-left font-mono text-xs text-fg-muted">Vulnerability</th>
              {scans.map((s) => (
                <th key={s.scanNumber} className="px-3 py-2 text-center font-mono text-xs text-fg-muted">#{s.scanNumber}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td colSpan={scans.length + 1} className="px-3 py-6 text-center font-mono text-sm text-fg-subtle">
                  No findings match this filter.
                </td>
              </tr>
            ) : (
              visible.map((row, i) => (
                <tr key={`${row.type}-${row.url}-${row.param}-${i}`} className="border-b border-border-muted">
                  <td className="sticky left-0 z-10 bg-bg-subtle px-3 py-2">
                    <div className="font-mono text-xs font-medium text-fg">{getVulnLabel(row.type)}</div>
                    <div className="max-w-[180px] truncate font-mono text-[10px] text-fg-subtle">{row.url}{row.param ? ` · ${row.param}` : ''}</div>
                  </td>
                  {scans.map((s) => {
                    const status = row.statusByScan[s.scanNumber];
                    const badge = STATUS_TO_BADGE[status];
                    return (
                      <td key={s.scanNumber} className="px-3 py-2 text-center">
                        {badge ? <Badge status={badge.status} showIcon={false} /> : <span className="text-fg-subtle">-</span>}
                      </td>
                    );
                  })}
                </tr>
              ))
            )}
          </tbody>
          <tfoot>
            <tr className="border-t border-border bg-bg-inset">
              <td className="sticky left-0 z-10 bg-bg-inset px-3 py-2 font-mono text-xs font-semibold text-fg">Security Score</td>
              {scans.map((s) => (
                <td key={s.scanNumber} className="px-3 py-2 text-center font-mono text-xs font-semibold text-accent">
                  {scoresByScan[s.scanNumber] ?? '-'}
                </td>
              ))}
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
}

export default ComparisonTable;
