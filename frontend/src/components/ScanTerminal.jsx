import { useRef, useEffect } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

// ScanTerminal — scrolling, virtualized log view. Handles 10k+ lines without
// jank via @tanstack/react-virtual. Auto-scrolls to the newest line unless the
// user has scrolled up. Each log: { timestamp?, message, type }.

const TYPE_CLS = {
  info: 'text-fg-muted',
  req: 'text-severity-low/80',
  found: 'text-accent',
  error: 'text-severity-critical',
  success: 'text-accent',
  warn: 'text-severity-medium',
};

export function ScanTerminal({ logs = [], height = 280 }) {
  const parentRef = useRef(null);
  const stickToBottom = useRef(true);

  const rowVirtualizer = useVirtualizer({
    count: logs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 20,
    overscan: 12,
  });

  // Track whether the user is pinned to the bottom.
  const onScroll = () => {
    const el = parentRef.current;
    if (!el) return;
    stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  useEffect(() => {
    if (stickToBottom.current && logs.length > 0) {
      rowVirtualizer.scrollToIndex(logs.length - 1, { align: 'end' });
    }
  }, [logs.length, rowVirtualizer]);

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-1.5 border-b border-border px-3 py-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-severity-critical/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-severity-medium/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-accent/70" />
        <span className="ml-2 font-mono text-[11px] text-fg-subtle">scan.log</span>
      </div>
      <div ref={parentRef} onScroll={onScroll} className="crt overflow-auto bg-bg-inset px-3 py-2 font-mono text-xs leading-5" style={{ height }}>
        {logs.length === 0 ? (
          <div className="text-fg-subtle">
            <span className="terminal-cursor">waiting for output</span>
          </div>
        ) : (
          <div style={{ height: rowVirtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {rowVirtualizer.getVirtualItems().map((vi) => {
              const log = logs[vi.index];
              return (
                <div
                  key={vi.key}
                  className="absolute left-0 top-0 flex w-full gap-2 whitespace-pre-wrap break-all"
                  style={{ transform: `translateY(${vi.start}px)`, height: vi.size }}
                >
                  {log.timestamp && <span className="shrink-0 text-fg-subtle">{log.timestamp}</span>}
                  <span className="shrink-0 text-accent/70">›</span>
                  <span className={TYPE_CLS[log.type] || TYPE_CLS.info}>{log.message}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

export default ScanTerminal;
