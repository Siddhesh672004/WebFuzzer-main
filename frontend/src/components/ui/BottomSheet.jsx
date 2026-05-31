import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';

// BottomSheet — mobile-first sheet that slides up from the bottom with a drag
// handle. Drag down past a threshold (or tap backdrop) to dismiss. Portals to
// <body>. Used by VulnDetailSheet on phones and any other mobile interaction.

export function BottomSheet({ isOpen, onClose, title, children, height = 'max-h-[85vh]' }) {
  useEffect(() => {
    if (!isOpen) return undefined;
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 z-50 flex items-end"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
          <motion.div
            role="dialog"
            aria-modal="true"
            className={`relative z-10 w-full overflow-y-auto rounded-t-2xl border-t border-border bg-bg-subtle ${height}`}
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            transition={{ type: 'spring', stiffness: 320, damping: 34 }}
            drag="y"
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.4 }}
            onDragEnd={(_e, info) => {
              if (info.offset.y > 120 || info.velocity.y > 600) onClose?.();
            }}
          >
            <div className="sticky top-0 z-10 flex flex-col items-center bg-bg-subtle pt-2">
              <div className="mb-2 h-1.5 w-10 rounded-full bg-border" aria-hidden="true" />
              {title && (
                <div className="mb-1 w-full border-b border-border px-4 pb-2 font-mono text-sm font-semibold text-fg">
                  {title}
                </div>
              )}
            </div>
            <div className="px-4 pb-6">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export default BottomSheet;
