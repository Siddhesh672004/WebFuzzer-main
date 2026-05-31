import { useState } from 'react';

// Tooltip — lightweight hover/focus tooltip. CSS-positioned, no portal (keeps it
// simple); the trigger wraps its children. `content` is the tip text/node.

export function Tooltip({ content, children, side = 'top', className = '' }) {
  const [open, setOpen] = useState(false);

  const pos = {
    top: 'bottom-full left-1/2 -translate-x-1/2 mb-1.5',
    bottom: 'top-full left-1/2 -translate-x-1/2 mt-1.5',
    left: 'right-full top-1/2 -translate-y-1/2 mr-1.5',
    right: 'left-full top-1/2 -translate-y-1/2 ml-1.5',
  }[side];

  return (
    <span
      className={`relative inline-flex ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && content && (
        <span
          role="tooltip"
          className={`pointer-events-none absolute z-50 whitespace-nowrap rounded border border-border bg-bg-inset px-2 py-1 font-mono text-[11px] text-fg shadow-lg ${pos}`}
        >
          {content}
        </span>
      )}
    </span>
  );
}

export default Tooltip;
