// Small, theme-consistent UI primitives. Kept minimal and dependency-free so
// every page shares the same look without re-declaring Tailwind class soup.

export function Button({ children, variant = 'primary', loading = false, className = '', disabled, ...props }) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 font-mono text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-accent/50 disabled:cursor-not-allowed disabled:opacity-50';
  const variants = {
    primary: 'bg-accent-dim text-white hover:bg-accent-glow',
    ghost: 'border border-border text-fg hover:bg-bg-subtle',
    danger: 'bg-severity-critical/90 text-white hover:bg-severity-critical',
  };
  return (
    <button
      className={`${base} ${variants[variant] || variants.primary} ${className}`}
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
        className={`w-full rounded-md border bg-bg-inset px-3 py-2.5 font-mono text-fg placeholder:text-fg-subtle focus:outline-none focus:ring-2 focus:ring-accent/40 ${
          error ? 'border-severity-critical' : 'border-border'
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
    <div className={`rounded-md border px-3 py-2.5 font-mono text-sm ${variants[variant] || variants.info}`} role="alert">
      {children}
    </div>
  );
}
