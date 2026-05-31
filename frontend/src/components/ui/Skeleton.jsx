// Skeleton — content placeholder shown while data loads. Pure CSS pulse, theme
// tokens. Compose `count` lines or use the preset block shapes.

export function Skeleton({ className = '', count = 1 }) {
  if (count > 1) {
    return (
      <div className="space-y-2">
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} className={`animate-pulse rounded bg-border/60 ${className || 'h-4 w-full'}`} />
        ))}
      </div>
    );
  }
  return <div className={`animate-pulse rounded bg-border/60 ${className || 'h-4 w-full'}`} />;
}

/** A card-shaped skeleton for list/table loading states. */
export function SkeletonCard() {
  return (
    <div className="card animate-pulse p-4">
      <div className="mb-3 h-4 w-1/3 rounded bg-border/60" />
      <div className="mb-2 h-3 w-2/3 rounded bg-border/50" />
      <div className="h-3 w-1/2 rounded bg-border/40" />
    </div>
  );
}

export default Skeleton;
