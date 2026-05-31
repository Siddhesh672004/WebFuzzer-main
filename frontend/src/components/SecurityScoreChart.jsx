import { LineChart, Line, XAxis, YAxis, Tooltip as RTooltip, ResponsiveContainer, CartesianGrid, ReferenceLine } from 'recharts';
import { TrendingUp, TrendingDown } from 'lucide-react';

// SecurityScoreChart — score trend across a target's scans (recharts LineChart).
// Dark themed; shows an improvement/decline badge comparing latest vs first.

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded border border-border bg-bg-inset px-2 py-1.5 font-mono text-xs">
      <div className="text-fg">Scan #{p.scanNumber}</div>
      <div className="text-accent">{p.score}/100</div>
      {p.date && <div className="text-fg-subtle">{p.date}</div>}
    </div>
  );
}

export function SecurityScoreChart({ history = [], height = 220 }) {
  if (!history.length) {
    return <div className="card flex h-40 items-center justify-center font-mono text-sm text-fg-muted">No scan history yet</div>;
  }

  const data = history.map((h) => ({
    scanNumber: h.scanNumber,
    score: h.score,
    date: h.date,
    label: `#${h.scanNumber}`,
  }));

  const first = data[0].score;
  const last = data[data.length - 1].score;
  const delta = last - first;

  return (
    <div className="card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="font-mono text-sm font-semibold text-fg">Security Score Trend</h3>
        {data.length > 1 && delta !== 0 && (
          <span
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-xs font-medium ${
              delta > 0 ? 'bg-accent/15 text-accent' : 'bg-severity-critical/15 text-severity-critical'
            }`}
          >
            {delta > 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
            {delta > 0 ? '+' : ''}{delta}
          </span>
        )}
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#21262D" />
          <XAxis dataKey="label" stroke="#6E7681" tick={{ fontSize: 11, fontFamily: 'monospace' }} />
          <YAxis domain={[0, 100]} stroke="#6E7681" tick={{ fontSize: 11, fontFamily: 'monospace' }} />
          <RTooltip content={<ChartTooltip />} />
          <ReferenceLine y={90} stroke="#3FB950" strokeDasharray="2 4" strokeOpacity={0.4} />
          <ReferenceLine y={40} stroke="#F85149" strokeDasharray="2 4" strokeOpacity={0.4} />
          <Line
            type="monotone"
            dataKey="score"
            stroke="#3FB950"
            strokeWidth={2}
            dot={{ r: 4, fill: '#3FB950', strokeWidth: 0 }}
            activeDot={{ r: 6 }}
            isAnimationActive
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SecurityScoreChart;
