import { Zap, Gauge, Radar } from 'lucide-react';

// ScanPresetSelector — Quick / Standard / Deep cards. Each preset maps to scan
// config (maxDepth, rateLimit, maxEndpoints). The selected preset glows green.
// Parent receives the preset object via onChange.

export const SCAN_PRESETS = {
  quick: {
    id: 'quick', name: 'Quick', Icon: Zap, time: '1–2 min',
    config: { maxDepth: 1, maxEndpoints: 50, rateLimit: 20 },
    includes: ['Shallow crawl', 'Passive + exposed files', 'Top payloads only'],
  },
  standard: {
    id: 'standard', name: 'Standard', Icon: Gauge, time: '10–15 min',
    config: { maxDepth: 3, maxEndpoints: 300, rateLimit: 10 },
    includes: ['Full crawl', 'All six modules', 'Curated payload set', 'Mutation engine'],
  },
  deep: {
    id: 'deep', name: 'Deep', Icon: Radar, time: '30+ min',
    config: { maxDepth: 5, maxEndpoints: 1000, rateLimit: 8 },
    includes: ['Exhaustive crawl', 'All modules', 'Extended payloads', 'Aggressive mutation'],
  },
};

export function ScanPresetSelector({ value = 'standard', onChange }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {Object.values(SCAN_PRESETS).map((preset) => {
        const selected = value === preset.id;
        const { Icon } = preset;
        return (
          <button
            key={preset.id}
            type="button"
            onClick={() => onChange?.(preset.id, preset)}
            className={`flex flex-col rounded-lg border p-4 text-left transition-all ${
              selected
                ? 'border-accent bg-accent/5 shadow-[0_0_0_1px_rgba(63,185,80,0.4)]'
                : 'border-border bg-bg-subtle hover:border-border-muted'
            }`}
          >
            <div className="mb-2 flex items-center gap-2">
              <Icon size={18} className={selected ? 'text-accent' : 'text-fg-muted'} />
              <span className="font-mono text-sm font-semibold text-fg">{preset.name}</span>
            </div>
            <span className="mb-2 font-mono text-xs text-fg-subtle">{preset.time}</span>
            <ul className="space-y-0.5">
              {preset.includes.map((item) => (
                <li key={item} className="font-mono text-[11px] text-fg-muted">• {item}</li>
              ))}
            </ul>
          </button>
        );
      })}
    </div>
  );
}

export default ScanPresetSelector;
