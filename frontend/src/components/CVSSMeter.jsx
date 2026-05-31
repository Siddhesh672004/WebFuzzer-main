import { motion } from 'framer-motion';

// CVSSMeter — parses a CVSS:3.1 vector string into its 8 base metrics and renders
// a score circle plus animated metric bars. The "dots" per metric encode the
// metric's contribution (more dots = worse), per the mapping in the PRD spec.

const METRIC_LABELS = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
};

const VALUE_LABELS = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { H: 'High', L: 'Low', N: 'None' },
  I: { H: 'High', L: 'Low', N: 'None' },
  A: { H: 'High', L: 'Low', N: 'None' },
};

// Dots out of 4 (higher = more severe contribution).
const DOTS = {
  AV: { N: 4, A: 3, L: 2, P: 1 },
  AC: { L: 4, H: 2 },
  PR: { N: 4, L: 2, H: 1 },
  UI: { N: 4, R: 2 },
  S: { C: 4, U: 2 },
  C: { H: 4, L: 2, N: 1 },
  I: { H: 4, L: 2, N: 1 },
  A: { H: 4, L: 2, N: 1 },
};

const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

export function parseVector(vector = '') {
  const out = {};
  for (const part of vector.replace(/^CVSS:3\.\d\//, '').split('/')) {
    const [k, v] = part.split(':');
    if (k && v) out[k] = v;
  }
  return out;
}

function scoreColor(score) {
  if (score >= 9) return 'text-severity-critical';
  if (score >= 7) return 'text-severity-high';
  if (score >= 4) return 'text-severity-medium';
  if (score > 0) return 'text-severity-low';
  return 'text-severity-info';
}
function barColor(score) {
  if (score >= 9) return 'bg-severity-critical';
  if (score >= 7) return 'bg-severity-high';
  if (score >= 4) return 'bg-severity-medium';
  if (score > 0) return 'bg-severity-low';
  return 'bg-severity-info';
}

export function CVSSMeter({ vector = '', score = 0, compact = false }) {
  const metrics = parseVector(vector);
  const fill = barColor(score);

  return (
    <div className={`flex ${compact ? 'flex-row items-center gap-4' : 'flex-col gap-4 sm:flex-row sm:items-start'}`}>
      {/* Score circle */}
      <div className="flex shrink-0 flex-col items-center">
        <div className={`flex h-20 w-20 items-center justify-center rounded-full border-4 border-current ${scoreColor(score)}`}>
          <motion.span
            className="font-mono text-2xl font-bold"
            initial={{ opacity: 0, scale: 0.6 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4 }}
          >
            {Number(score).toFixed(1)}
          </motion.span>
        </div>
        <span className="mt-1 font-mono text-[10px] uppercase tracking-wide text-fg-muted">CVSS 3.1</span>
      </div>

      {/* Metric bars */}
      <div className="grid flex-1 grid-cols-1 gap-1.5 sm:grid-cols-2">
        {ORDER.filter((k) => metrics[k]).map((k, i) => {
          const v = metrics[k];
          const dots = DOTS[k]?.[v] ?? 0;
          return (
            <div key={k} className="flex items-center gap-2">
              <span className="w-28 shrink-0 font-mono text-[11px] text-fg-muted">{METRIC_LABELS[k]}</span>
              <div className="flex flex-1 gap-0.5">
                {[1, 2, 3, 4].map((d) => (
                  <motion.div
                    key={d}
                    className={`h-1.5 flex-1 rounded-sm ${d <= dots ? fill : 'bg-border'}`}
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ delay: i * 0.04 + d * 0.02, duration: 0.25 }}
                    style={{ transformOrigin: 'left' }}
                  />
                ))}
              </div>
              <span className="w-20 shrink-0 text-right font-mono text-[10px] text-fg-subtle">
                {VALUE_LABELS[k]?.[v] || v}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default CVSSMeter;
