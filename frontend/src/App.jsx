import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute.jsx';

// App shell. Routes are code-split with React.lazy so the Verify page loads
// without pulling in chart/animation libraries (frontend performance plan,
// IMPLEMENTATION_PLAN §12). Phase 1 ships Verify + a protected Dashboard;
// Phase 5 adds the remaining pages.

const Verify = lazy(() => import('./pages/Verify.jsx'));
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'));

function PageFallback() {
  return (
    <div className="flex h-screen items-center justify-center text-fg-muted font-mono">
      <span className="terminal-cursor">loading</span>
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/verify" element={<Verify />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        {/* Phase 5 adds: /scan/new, /scan/:id, /results/:id, /reports,
            /compare/:domain — each wrapped in ProtectedRoute. */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  );
}
