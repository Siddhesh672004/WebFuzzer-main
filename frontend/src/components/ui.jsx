// Small, theme-consistent UI primitives. Kept minimal and dependency-free so
// every page shares the same look without re-declaring Tailwind class soup.
// Interaction physics live in index.css (.pressable / .btn-*): scale(0.97) on
// press, 160ms ease-out, hover states gated to real pointers.

export function Button({ children, variant = 'primary', loading = false, className = '', disabled, ...props }) {
  const base = 'px-4 py-2.5 font-mono text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/50';
  const variants = {
    // Phosphor accent with near-black text; the glow appears on hover only.
    primary: 'btn-primary',
    ghost: 'btn-ghost',
    danger: 'btn pressable bg-severity-critical/90 text-white hover:bg-severity-critical',
  };
  return (
    <button
      className={`${variants[variant] || variants.primary} ${base} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span
          className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
          aria-hidden="true"
        />
      )}
      {children}
    </button>
  );
}

export function Input({ label, error, className = '', id, ...props }) {
  return (
    <div className="w-full">
      {label && (
        <label htmlFor={id} className="mb-1.5 block font-mono text-xs uppercase tracking-wide text-fg-muted">
          {label}
        </label>
      )}
      <input
        id={id}
        className={`w-full rounded-md border bg-bg-inset px-3 py-2.5 font-mono text-fg placeholder:text-fg-subtle transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-accent/40 ${
          error ? 'border-severity-critical' : 'border-border focus:border-accent/50'
        } ${className}`}
        aria-invalid={!!error}
        {...props}
      />
      {error && <p className="mt-1.5 font-mono text-xs text-severity-critical">{error}</p>}
    </div>
  );
}

export function Alert({ children, variant = 'info' }) {
  const variants = {
    info: 'border-severity-low/40 bg-severity-low/10 text-severity-low',
    error: 'border-severity-critical/40 bg-severity-critical/10 text-severity-critical',
    success: 'border-accent/40 bg-accent/10 text-accent',
    warn: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium',
  };
  return (
    <div className={`animate-slide-up rounded-md border px-3 py-2.5 font-mono text-sm ${variants[variant] || variants.info}`} role="alert">
      {children}
    </div>
  );
}
