import { useEffect } from 'react';
import { motion, useMotionValue, useTransform, animate } from 'framer-motion';
import { ProgressBar } from './ui/ProgressBar.jsx';

// SecurityScoreGauge — large animated 0–100 score that counts up on mount, with
// a band label and color-coded progress bar. Bands match the PRD §7.4 scale.

const BANDS = {
  secure: { label: 'Secure', cls: 'text-accent' },
  needs_attention: { label: 'Needs Attention', cls: 'text-severity-medium' },
  vulnerable: { label: 'Vulnerable', cls: 'text-severity-high' },
  critical_risk: { label: 'Critical Risk', cls: 'text-severity-critical' },
};

function bandFor(score) {
  if (score >= 90) return 'secure';
  if (score >= 70) return 'needs_attention';
  if (score >= 40) return 'vulnerable';
  return 'critical_risk';
}

export function SecurityScoreGauge({ score = 0, band, size = 'lg' }) {
  const resolvedBand = band || bandFor(score);
  const meta = BANDS[resolvedBand] || BANDS.critical_risk;

  const count = useMotionValue(0);
  const rounded = useTransform(count, (v) => Math.round(v));

  useEffect(() => {
    const controls = animate(count, score, { duration: 0.9, ease: 'easeOut' });
    return controls.stop;
  }, [score, count]);

  const numSize = size === 'sm' ? 'text-3xl' : size === 'md' ? 'text-5xl' : 'text-6xl';

  return (
    <div className="flex flex-col items-center">
      <div className="flex items-baseline gap-1">
        <motion.span className={`font-mono font-bold ${numSize} ${meta.cls}`}>{rounded}</motion.span>
        <span className="font-mono text-lg text-fg-subtle">/100</span>
      </div>
      <span className={`mt-1 font-mono text-xs font-semibold uppercase tracking-wide ${meta.cls}`}>{meta.label}</span>
      <ProgressBar value={score} scoreColor className="mt-2 w-40" height="h-2" />
    </div>
  );
}

export default SecurityScoreGauge;
