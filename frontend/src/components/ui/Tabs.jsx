import { useState } from 'react';
import { motion } from 'framer-motion';

// Tabs — accessible-ish tab strip with an animated active underline (framer
// shared layout). Controlled or uncontrolled. `tabs` is [{ id, label, icon? }].

export function Tabs({ tabs = [], value, defaultValue, onChange, className = '' }) {
  const [internal, setInternal] = useState(defaultValue ?? tabs[0]?.id);
  const active = value !== undefined ? value : internal;

  const select = (id) => {
    if (value === undefined) setInternal(id);
    onChange?.(id);
  };

  return (
    <div className={`flex gap-1 border-b border-border ${className}`} role="tablist">
      {tabs.map((t) => {
        const isActive = t.id === active;
        const Icon = t.icon;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => select(t.id)}
            className={`relative flex items-center gap-1.5 px-3 py-2 font-mono text-xs font-medium transition-colors ${
              isActive ? 'text-accent' : 'text-fg-muted hover:text-fg'
            }`}
          >
            {Icon && <Icon size={14} />}
            {t.label}
            {isActive && (
              <motion.span
                layoutId="tab-underline"
                className="absolute inset-x-0 -bottom-px h-0.5 bg-accent"
                transition={{ type: 'spring', stiffness: 400, damping: 32 }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}

export default Tabs;
