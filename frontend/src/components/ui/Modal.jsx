import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';

// Modal — centered dialog with backdrop. Portals to <body>, closes on Esc or
// backdrop click, and traps nothing fancy (the app is single-purpose). Animated
// with framer-motion. For mobile bottom-sheet UX use BottomSheet instead.

export function Modal({ isOpen, onClose, title, children, className = '', maxWidth = 'max-w-lg' }) {
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
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
          <motion.div
            role="dialog"
            aria-modal="true"
            className={`card relative z-10 w-full ${maxWidth} ${className}`}
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
          >
            {(title || onClose) && (
              <div className="flex items-center justify-between border-b border-border px-4 py-3">
                <h3 className="font-mono text-sm font-semibold text-fg">{title}</h3>
                <button onClick={onClose} className="text-fg-muted hover:text-fg" aria-label="Close">
                  <X size={18} />
                </button>
              </div>
            )}
            <div className="p-4">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export default Modal;
