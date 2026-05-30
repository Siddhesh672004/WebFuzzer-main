import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';

// App shell. Routes are code-split with React.lazy so the Verify page loads
// without pulling in chart/animation libraries (frontend performance plan,
// IMPLEMENTATION_PLAN §12). Real pages arrive in Phase 1 (Verify) and Phase 5
// (the rest); for now a single placeholder proves the shell renders and routes.

const Verify = lazy(() => import('./pages/Verify.jsx'));

function PageFallback() {
  return (
    <div className="flex h-full items-center justify-center text-fg-muted font-mono">
      <span className="terminal-cursor">loading</span>
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/verify" element={<Verify />} />
        {/* Phase 5 adds: /dashboard, /scan/new, /scan/:id, /results/:id,
            /reports, /compare/:domain. For now, route everything to Verify. */}
        <Route path="*" element={<Navigate to="/verify" replace />} />
      </Routes>
    </Suspense>
  );
}
