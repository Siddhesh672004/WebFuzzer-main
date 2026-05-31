import { motion } from 'framer-motion';

// ProgressBar — animated horizontal bar. `value` is 0–100. Color can be driven
// by an explicit `tone` or derived from a score band when `scoreColor` is set.

function bandColor(v) {
  if (v >= 90) return 'bg-accent';
  if (v >= 70) return 'bg-severity-medium';
  if (v >= 40) return 'bg-severity-high';
  return 'bg-severity-critical';
}

export function ProgressBar({ value = 0, tone, scoreColor = false, className = '', height = 'h-2', showLabel = false, animate = true }) {
  const pct = Math.max(0, Math.min(100, value));
  const color = tone || (scoreColor ? bandColor(pct) : 'bg-accent');

  return (
    <div className={className}>
      <div className={`w-full overflow-hidden rounded-full bg-bg-inset ${height}`}>
        <motion.div
          className={`${height} rounded-full ${color}`}
          initial={animate ? { width: 0 } : false}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
      </div>
      {showLabel && <div className="mt-1 text-right font-mono text-xs text-fg-muted">{Math.round(pct)}%</div>}
    </div>
  );
}

export default ProgressBar;
